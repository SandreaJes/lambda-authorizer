const chai = require("chai");
const index = require("../src/index.js");
const awsMock = require("aws-sdk-mock");

const should = chai.should();

let context;

chai.use(require("chai-string"));

describe("Tests index", () => {
  awsMock.mock("SSM", "getParameter", (params, callback) => {
    callback(null, { Parameter: { Value: "secret" } });
  });

  process.env.SSM_SECRET_KEY_NAME = "jwt.secret";
  process.env.ENVNAME = "test";
  process.env.SSM_APPLICATION = "salaryloans";
  process.env.ACCES_TOKEN_TIME_OUT = 3000;

  it("verifies successful response for request", done => {
    const event = {
      queryStringParameters: {
        Authorization:
          "U2FsdGVkX19wRtY3mj9D4QiS7JmePstVZlyynoCSmj0FGWbXNF6Ii6sZ7OFxa3glpJwScxZGj2n/nk0yzsDVZDQibBtJu+laWqarcR1EFG2PrY0Iycor4sYfDhc0FR9jYDvyJ1ZPmr+Vin2GPis5x5h7ttu+cIrLbyY6a1PofT4tP/t/oKL2c4asEZ+dHwtodZdPIu6yF6j0FFJxbnANGkdUtB8tnUFXqCbkAHp22W6QyU5sL1P8mFOqkbbLHDdHm2B6SaSEpS7oJQeySPYnqLfe59XTlXTTTFrBMHpzzC3xBnLIjX3x+/k9Xy0B+xv8iQWYqYmsjn2FZibJTVHyvy6v3T6LXeh1R9nl2ndUlcZG/QSpn6sUl/+tes6qaME0ZivppRa49APTUNh+qoVdm9WBTCiICUIDbfH5SqNX8KiV1mq7mFiOIPyCKzwEr9hJ7RyQ5XadzHGPNIO/TLKy3f7s0CtVtJcPr+J5ZRcUtuhTVWHTU1ZYEamqFCclxezHrXGXdKuv2UGEpCGZIUnLS8YVo8rR7Sg2cGEtxY+SYoKB+WBO/r4KA13i5ckDZg9JSYuJTmULdXJKgkVnDmhh7040GampPGX7eKEdiLa4QihqeXFQJq4b/E6aDkn1ASwh"
      },
      methodArn: "arn:aws:execute-api:us-west-2:111111:2222222/v1/GET/method",
      type: "REQUEST"
    };
    index.handler(event, context, (err, res) => {
      try {
        should.not.exist(err);
        should.exist(res);
        res.should.be.a("object");
        done();
      } catch (e) {
        done(e);
      }
    });
  });
  it("verifies successful response for token", done => {
    const event = {
      authorizationToken:
        "U2FsdGVkX19wRtY3mj9D4QiS7JmePstVZlyynoCSmj0FGWbXNF6Ii6sZ7OFxa3glpJwScxZGj2n/nk0yzsDVZDQibBtJu+laWqarcR1EFG2PrY0Iycor4sYfDhc0FR9jYDvyJ1ZPmr+Vin2GPis5x5h7ttu+cIrLbyY6a1PofT4tP/t/oKL2c4asEZ+dHwtodZdPIu6yF6j0FFJxbnANGkdUtB8tnUFXqCbkAHp22W6QyU5sL1P8mFOqkbbLHDdHm2B6SaSEpS7oJQeySPYnqLfe59XTlXTTTFrBMHpzzC3xBnLIjX3x+/k9Xy0B+xv8iQWYqYmsjn2FZibJTVHyvy6v3T6LXeh1R9nl2ndUlcZG/QSpn6sUl/+tes6qaME0ZivppRa49APTUNh+qoVdm9WBTCiICUIDbfH5SqNX8KiV1mq7mFiOIPyCKzwEr9hJ7RyQ5XadzHGPNIO/TLKy3f7s0CtVtJcPr+J5ZRcUtuhTVWHTU1ZYEamqFCclxezHrXGXdKuv2UGEpCGZIUnLS8YVo8rR7Sg2cGEtxY+SYoKB+WBO/r4KA13i5ckDZg9JSYuJTmULdXJKgkVnDmhh7040GampPGX7eKEdiLa4QihqeXFQJq4b/E6aDkn1ASwh",
      methodArn: "arn:aws:execute-api:us-west-2:111111:2222222/v1/GET/method",
      type: "TOKEN"
    };
    index.handler(event, context, (err, res) => {
      try {
        should.not.exist(err);
        should.exist(res);
        res.should.be.a("object");
        done();
      } catch (e) {
        done(e);
      }
    });
  });

  it("verifies expired token", done => {
    const event = {
      authorizationToken:
        "U2FsdGVkX19lR3DYuBPgEL0lMv8isSvQulHxPlbEOlOe/6z7dQWgVc50YDfMHoGEaA3pXhtobPoWmSdgITbVIAyvtXN+gkKvdEfLLDVVuOr9U4z8pLPLYe9fbI8Gry8ECUjT7RCHntRsoU1kUyEgyr0trUya7Yar44/LgBi1Xx10HMr+rjYCZ3QsHBMVWmZ9+d1duYlFsB+h8ViNXGje9VHx/JvMTmlJo6HQaGP2p43alnRClEM+/bknUPiaYVOFsg2WEQIy4HT0OityAls4Ze/f01ws7uckfYmVVZd66TXCaKwz8Gtsz2+c2FGuh18kuwS21wZKj4z2AYMJRG+eGCxzAUDS76mpX85DzjSGydZ177w6GTYE/vqNbNnNR9zWw6ygmLL/hgJBKzEmIWLJliVd0A/ui5Uv7Gr+2RfZevm4Ot+RO55YNdEGV6upJ0T8LTGjmvVAf2wQlqB4nH/QRZAHAribdq2FvFvBy3dAPsKBN/UJ8p/e8tlCFccm89lxqnrw+HbKg0MjE/nk40lYtug5rLnjWBh5lF4g1bsH7Unue9GG5z5BE+4nkZS9XW5OPkPWc9y3zM4RQxje/k5Ecm4Uk+zk5Ygl3c0dTGAqDgtn5ogedQGLa230nB4tjVPC",
      methodArn: "arn:aws:execute-api:us-west-2:111111:2222222/v1/GET/method",
      type: "TOKEN"
    };
    index.handler(event, context, (err, res) => {
      try {
        should.exist(err);
        should.not.exist(res);
        err.should.equal("Unauthorized");
        done();
      } catch (e) {
        done(e);
      }
    });
  });

  it("verifies invalid token", done => {
    const event = {
      authorizationToken: "U2FsdGVkX18zJl3zv4zJVrDQwXu496lMmJOrwGRpvhE=",
      methodArn: "arn:aws:execute-api:us-west-2:111111:2222222/v1/GET/method",
      type: "TOKEN"
    };
    index.handler(event, context, (err, res) => {
      try {
        should.exist(err);
        should.not.exist(res);
        err.should.equal("Unauthorized");
        done();
      } catch (e) {
        done(e);
      }
    });
  });

  it("verifies empty token", done => {
    const event = {
      authorizationToken: null,
      methodArn: "arn:aws:execute-api:us-west-2:111111:2222222/v1/GET/method",
      type: "TOKEN"
    };
    index.handler(event, context, (err, res) => {
      try {
        should.exist(err);
        should.not.exist(res);
        err.should.equal("Unauthorized");
        done();
      } catch (e) {
        done(e);
      }
    });
  });

  it("verifies empty arn", done => {
    const event = {
      authorizationToken:
        "U2FsdGVkX19wRtY3mj9D4QiS7JmePstVZlyynoCSmj0FGWbXNF6Ii6sZ7OFxa3glpJwScxZGj2n/nk0yzsDVZDQibBtJu+laWqarcR1EFG2PrY0Iycor4sYfDhc0FR9jYDvyJ1ZPmr+Vin2GPis5x5h7ttu+cIrLbyY6a1PofT4tP/t/oKL2c4asEZ+dHwtodZdPIu6yF6j0FFJxbnANGkdUtB8tnUFXqCbkAHp22W6QyU5sL1P8mFOqkbbLHDdHm2B6SaSEpS7oJQeySPYnqLfe59XTlXTTTFrBMHpzzC3xBnLIjX3x+/k9Xy0B+xv8iQWYqYmsjn2FZibJTVHyvy6v3T6LXeh1R9nl2ndUlcZG/QSpn6sUl/+tes6qaME0ZivppRa49APTUNh+qoVdm9WBTCiICUIDbfH5SqNX8KiV1mq7mFiOIPyCKzwEr9hJ7RyQ5XadzHGPNIO/TLKy3f7s0CtVtJcPr+J5ZRcUtuhTVWHTU1ZYEamqFCclxezHrXGXdKuv2UGEpCGZIUnLS8YVo8rR7Sg2cGEtxY+SYoKB+WBO/r4KA13i5ckDZg9JSYuJTmULdXJKgkVnDmhh7040GampPGX7eKEdiLa4QihqeXFQJq4b/E6aDkn1ASwh",
      methodArn: null,
      type: "TOKEN"
    };
    index.handler(event, context, (err, res) => {
      try {
        should.exist(err);
        should.not.exist(res);
        err.should.equal("Unauthorized");
        done();
      } catch (e) {
        done(e);
      }
    });
  });
});
