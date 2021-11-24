"use strict";
const jwtPlugin = require("jsonwebtoken");
const crypto = require("crypto-js");
const AWS = require("aws-sdk");

let secretKey = null;
let ssm = null;

/**
 * Validate the incoming token and produce the principal user identifier associated with the token.
 *
 * This could be accomplished in a number of ways:
 * 1. Call out to OAuth provider
 * 2. Decode a JWT token inline
 * 3. Lookup in a self-managed DB
 *
 * TODO. Validate token against backend OAuth authorization server.
 * @Param {string} accessToken The token provided
 * @Return {void}
 */
function validateToken(accessToken) {
  console.log("Validate token: " + accessToken);
  return new Promise(function(resolve, reject) {
    const decrypted = crypto.AES.decrypt(accessToken, secretKey).toString(
      crypto.enc.Utf8
    );

    console.log("Decrypted Token: ", decrypted);
    const tokenParts = decrypted.split(".");
    if (tokenParts.length !== 3) {
      // eslint-disable-next-line prefer-promise-reject-errors
      reject({ success: false, message: "Invalid token" });
    }

    const buff = new Buffer(tokenParts[1], "base64");
    const text = buff.toString("ascii");

    console.log("Token payload: " + text);

    const profileInfo = JSON.parse(text);
    const dateTimeNow = Math.round(new Date().getTime() / 1000);

    if (dateTimeNow > profileInfo.exp) {
      // eslint-disable-next-line prefer-promise-reject-errors
      reject({ success: false, message: "Expired token" });
    }

    // Add new expiration time
    profileInfo.exp = dateTimeNow + parseInt(process.env.ACCES_TOKEN_TIME_OUT);
    console.log("accesToken exp in method validateToken", profileInfo.exp);
    resolve({
      success: true,
      data: accessToken,
      nextAccessToken: accessToken
    });
  });
}

/**
 * Function to generate internal Token
 * @Param {any} profileInfo The response info from validated token
 * @Return {string} the new token
 */
function generateInternalToken(profileInfo) {
  return jwtPlugin.sign(profileInfo, secretKey);
}

/**
 * Function to extract the elements from event.methodArn
 * The value of 'arn' follows the format shown below:
 * @Param {string} methodArn full arn
 ex arn:aws:execute-api:<regionid>:<accountid>:<apiid>/<stage>/<method>/<resourcepath>
 * @Return {object} the arn info.
 */
function extractArnElements(methodArn) {
  // Extract information from method arn
  console.log("Method ARN:", methodArn);
  if (!methodArn) {
    // Invalid Method ARN.
    throw new Error("[" + methodArn + "] " + " -> Invalid Method ARN.");
  }

  const methodArnElements = methodArn.split(":", 6);
  const resourceElements = methodArnElements[5].split("/", 4);

  return {
    regionId: methodArnElements[3],
    accountId: methodArnElements[4],
    apiId: resourceElements[0],
    stage: resourceElements[1],
    method: resourceElements[2],
    resourcePath: resourceElements[3]
  };
}

/**
 * Function to extract an access token by Authorizer type.
 * @Param {object} event the aws passed to lambda function
 * @return {string} token The authorization token
 */
function extractTokenByAuthorizerType(event) {
  // Extract the event type from authorizer
  let token = "";

  if (event.type === "REQUEST") {
    token = event.queryStringParameters.Authorization;
  } else {
    token = event.authorizationToken;
  }

  if (!token) {
    throw new Error("Invalid acces token" + token);
  }

  console.log("Client token:", token);

  return token;
}

/**
 * AuthPolicy receives a set of allowed and denied methods and generates a valid
 * AWS policy for the API Gateway authorizer. The constructor receives the calling
 * user principal, the AWS account ID of the API owner, and an apiOptions object.
 * The apiOptions can contain an API Gateway RestApi Id, a region for the RestApi, and a
 * stage that calls should be allowed/denied for. For example
 * {
 *   restApiId: 'xxxxxxxxxx,
 *   region: 'us-east-1,
 *   stage: 'dev',
 * }
 *
 * const testPolicy = new AuthPolicy("[principal user identifier]", "[AWS account id]", apiOptions);
 * testPolicy.allowMethod(AuthPolicy.HttpVerb.GET, "/users/username");
 * testPolicy.denyMethod(AuthPolicy.HttpVerb.POST, "/pets");
 * callback(null, testPolicy.build());
 * @Param {string} principal The principal user identifier
 * @Param {string} awsAccountId The AWS account id
 * @Param {object} apiOptions the policy options for this API
 *
 * @class AuthPolicy
 * @constructor
 */
function AuthPolicy(principal, awsAccountId, apiOptions) {
  /**
   * The AWS account id the policy will be generated for. This is used to create
   * the method ARNs.
   *
   * @property awsAccountId
   * @type {String}
   */
  this.awsAccountId = awsAccountId;

  /**
   * The principal used for the policy, this should be a unique identifier for
   * the end user.
   *
   * @property principalId
   * @type {String}
   */
  this.principalId = principal;

  /**
   * The policy version used for the evaluation. This should always be "2012-10-17"
   *
   * @property version
   * @type {String}
   * @default "2012-10-17"
   */
  this.version = "2012-10-17";

  /**
   * The regular expression used to validate resource paths for the policy
   *
   * @property pathRegex
   * @type {RegExp}
   * @default '^\/[/.a-zA-Z0-9-\*]+$'
   */
  this.pathRegex = new RegExp("^[/.a-zA-Z0-9-*]+$");

  // These are the internal lists of allowed and denied methods. These are lists
  // of objects and each object has two properties: a resource ARN and a nullable
  // conditions statement. The build method processes these lists and generates
  // the appropriate statements for the final policy.
  this.allowMethods = [];
  this.denyMethods = [];
  this.restApiId = apiOptions.restApiId;
  this.region = apiOptions.region;
  this.stage = apiOptions.stage;
}

/**
 * This function generates a policy that is associated with the recognized principal user identifier.
 * The policy is cached for 5 minutes by default (TTL is configurable in the authorizer),
 * and will apply to subsequent calls to any method/resource in the RestApi made with the same token.
 *
 * Policy methods:
 * Deny all: policy.denyAllMethods()
 * Allow all: policy.allowAllMethods()
 * Allow a specific method: policy.allowMethod(AuthPolicy.HttpVerb.GET, "/users/username")
 *
 * @param {object} arnElements
 * @param {string} principalId
 * @param {string} internalToken
 * @param {string} nextAccessToken
 * @return {*}
 */
function buildAuthPolicy(
  arnElements,
  principalId,
  internalToken,
  nextAccessToken
) {
  // Build apiOptions for the AuthPolicy
  const apiOptions = {
    region: arnElements.regionId,
    restApiId: arnElements.apiId,
    stage: arnElements.stage
  };
  const awsAccountId = arnElements.accountId;

  const policy = new AuthPolicy(principalId, awsAccountId, apiOptions);
  policy.allowAllMethods();
  const authPolicy = policy.build();

  authPolicy.context = {
    internalAuthorizationToken: "Bearer " + internalToken,
    nextAccessToken: nextAccessToken
  };

  console.log("Auth Policy", JSON.stringify(authPolicy));

  return authPolicy;
}

/**
 * This function generates a policy that is associated with the recognized principal user identifier.
 * The policy is cached for 5 minutes by default (TTL is configurable in the authorizer),
 * and will apply to subsequent calls to any method/resource in the RestApi made with the same token.
 *
 * @param {object} resource
 * @param {string} principalId
 * @param {string} internalToken
 * @param {string} nextAccessToken
 * @return {*}
 */
function buildWsPolicy(resource, principalId, internalToken, nextAccessToken) {
  // Required output:
  const authResponse = {};
  authResponse.principalId = principalId;
  authResponse.policyDocument = {
    Version: "2012-10-17",
    Statement: [
      {
        Action: "execute-api:Invoke",
        Effect: "Allow",
        Resource: resource
      }
    ]
  };

  authResponse.context = {
    internalAuthorizationToken: "Bearer " + internalToken,
    nextAccessToken: nextAccessToken
  };

  console.log("Ws Policy", JSON.stringify(authResponse));

  return authResponse;
}

/**
 * A set of existing HTTP verbs supported by API Gateway. This property is here
 * only to avoid spelling mistakes in the policy.
 *
 * @property HttpVerb
 * @type {Object}
 */
AuthPolicy.HttpVerb = {
  GET: "GET",
  POST: "POST",
  PUT: "PUT",
  PATCH: "PATCH",
  HEAD: "HEAD",
  DELETE: "DELETE",
  OPTIONS: "OPTIONS",
  ALL: "*"
};

AuthPolicy.prototype = (function AuthPolicyClass() {
  /**
   * Adds a method to the internal lists of allowed or denied methods. Each object in
   * the internal list contains a resource ARN and a condition statement. The condition
   * statement can be null.
   *
   * @method addMethod
   * @param {String} effect The effect for the policy. This can only be "Allow" or "Deny".
   * @param {String} verb The HTTP verb for the method, this should ideally come from the
   *                 AuthPolicy.HttpVerb object to avoid spelling mistakes
   * @param {String} resource The resource path. For example "/pets"
   * @param {Object} conditions The conditions object in the format specified by the AWS docs.
   * @return {void}
   */
  function addMethod(effect, verb, resource, conditions) {
    if (
      verb !== "*" &&
      !Object.prototype.hasOwnProperty.call(AuthPolicy.HttpVerb, verb)
    ) {
      throw new Error(
        `Invalid HTTP verb ${verb}. Allowed verbs in AuthPolicy.HttpVerb`
      );
    }

    // eslint-disable-next-line max-len
    const resourceArn = `arn:aws:execute-api:${this.region}:${this.awsAccountId}:${this.restApiId}/${this.stage}/${verb}/${resource}`;

    const effectMethod = effect.toLowerCase() + "Methods";
    this[effectMethod].push({
      resourceArn,
      conditions
    });
  }

  /**
   * Returns an empty statement object prepopulated with the correct action and the
   * desired effect.
   *
   * @method getEmptyStatement
   * @param {String} effect The effect of the statement, this can be "Allow" or "Deny"
   * @return {Object} An empty statement object with the Action, Effect, and Resource
   *                  properties pre populated.
   */
  function getEmptyStatement(effect) {
    const statement = {};
    statement.Action = "execute-api:Invoke";
    statement.Effect =
      effect.substring(0, 1).toUpperCase() +
      effect.substring(1, effect.length).toLowerCase();
    statement.Resource = [];

    return statement;
  }

  /**
   * This function loops over an array of objects containing a resourceArn and
   * conditions statement and generates the array of statements for the policy.
   *
   * @method getStatementsForEffect
   * @param {String} effect The desired effect. This can be "Allow" or "Deny"
   * @param {Array} methods An array of method objects containing the ARN of the resource
   *                and the conditions for the policy
   * @return {Array} an array of formatted statements for the policy.
   */
  function getStatementsForEffect(effect, methods) {
    const statements = [];

    if (methods.length > 0) {
      const statement = getEmptyStatement(effect);

      for (let i = 0; i < methods.length; i++) {
        const curMethod = methods[i];
        statement.Resource.push(curMethod.resourceArn);
      }

      if (statement.Resource !== null && statement.Resource.length > 0) {
        statements.push(statement);
      }
    }

    return statements;
  }

  return {
    constructor: AuthPolicy,

    /**
     * Adds an allow "*" statement to the policy.
     *
     * @method allowAllMethods
     */
    allowAllMethods() {
      addMethod.call(this, "allow", "*", "*", null);
    },

    /**
     * Generates the policy document based on the internal lists of allowed and denied
     * conditions. This will generate a policy with two main statements for the effect:
     * one statement for Allow and one statement for Deny.
     * Methods that includes conditions will have their own statement in the policy.
     *
     * @method build
     * @return {Object} The policy object that can be serialized to JSON.
     */
    build() {
      return {
        principalId: this.principalId,
        policyDocument: {
          Version: this.version,
          Statement: [
            getStatementsForEffect.call(this, "Allow", this.allowMethods),
            getStatementsForEffect.call(this, "Deny", this.denyMethods)
          ]
        }
      };
    }
  };
})();

/**
 * Ask parameter store for parameter by name
 * @param {string} name The full name of parameter
 * @return {Promise<PromiseResult<SSM.GetParameterResult, AWSError>>}
 */
function retrieveSSMParam(name) {
  if (ssm === null) {
    ssm = new AWS.SSM();
  }
  const paramName = `/${process.env.ENVNAME}/${process.env.SSM_APPLICATION}/${name}`;
  console.log("requested parameter", paramName);
  const ssmRequest = { Name: paramName, WithDecryption: true };
  return ssm.getParameter(ssmRequest).promise();
}

/**
 * Build
 * @param {object} validationResponse The info from the incoming token validated
 * @param {object} event the aws passed to lambda function
 * @param {object} arnElements
 * @return {*}
 */
function buildPolicy(validationResponse, event, arnElements) {
  if (event.type === "REQUEST") {
    console.log("Valid token for Websocket Resource Call");
    return buildWsPolicy(
      event.methodArn,
      validationResponse.data.jti,
      generateInternalToken(validationResponse.data),
      validationResponse.nextAccessToken
    );
  } else {
    console.log("Valid token for HTTP Resource Call");
    return buildAuthPolicy(
      arnElements,
      validationResponse.data.jti,
      generateInternalToken(validationResponse.data),
      validationResponse.nextAccessToken
    );
  }
}

/**
 * API Gateway custom authorizer, for an OAuth2 backend authorization server.
 *
 * You can send a 401 Unauthorized response to the client by failing like so:
 * callback('Unauthorized');
 * If the token is valid, a policy must be generated which will allow or deny access to the client.
 * If access is denied, the client will recieve a 403 Access Denied response.
 * If access is allowed, API Gateway will proceed with the backend integration configured on the method that was called.
 *
 * @param {object} event
 * @param {object} context
 * @param {callback} callback
 */
exports.handler = (event, context, callback) => {
  console.log("event: ", JSON.stringify(event));
  let arnElements;
  retrieveSSMParam(process.env.SSM_SECRET_KEY_NAME)
    .then(param => {
      secretKey = param.Parameter.Value;
      return secretKey;
    })
    .then(() => extractArnElements(event.methodArn))
    .then(arn => {
      arnElements = arn;
      return extractTokenByAuthorizerType(event);
    })
    .then(accessToken => validateToken(accessToken))
    .then(validationResponse =>
      buildPolicy(validationResponse, event, arnElements)
    )
    .then(policy => callback(null, policy))
    .catch(error => {
      console.error("Error:", error);
      callback("Unauthorized");
    });
};
