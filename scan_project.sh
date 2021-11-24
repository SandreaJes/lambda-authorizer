# Recorre cada lambda del proyecto
cd authorizer

echo '' >> sonar-project.properties
echo 'sonar.host.url='$SONAR_HOST_URL >> sonar-project.properties
echo "sonar.login="$SONAR_LOGIN >> sonar-project.properties
sonar-scanner
git checkout -- sonar-project.properties

cd ..
