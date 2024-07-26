**Especificaciones tecnicas del proyecto Vulnerabilities**
   
Uso de versiones:
python:3.10.10
Mysql 8.0

**Clone the repositorio**

https://github.com/sebassuaza98/Vulnerabilities.git
* Al clonar Cree un archivo en la raiz del proyecto que se va a llamar: script.sh, el contenido del archivo esta djunto en el correo.

**Prerequisites**
El proyecto ha sido dockerizado, por lo que para ejecutarlo se nesecita tener instalado docker.

Una vez intalado docker y clonado el repositorio, abrir el el proyeto en su IDE de preferencia.
Al abrirlo ejecutar en consola:
* cd security_manager
* docker-compose build     
* docker-compose up -d  

** Nota**
* El Api cuenta con pruebas Unitarias, depositadas en el archivo tests.py

Ya una vez ejecutados los comando anteriores, mla imagen esta lista y las peticiones podran ser consumidas.
* La forma de consumir las peticones esta anexadas al correo con el nombre de **Instructivo de consumo de API**

**Diagrama**
+----------------------------+
|       Django Project       |
|        (security_manager)  |
+----------------------------+
            |
            v
+----------------------------+
|       vulnerabilities      |
|         Application        |
+----------------------------+
            |
            v
+----------------------------+                +----------------------+
|          Models            |                |      Database        |
+----------------------------+                |      (MySQL)         |
| Vulnerability              | <------------> |                      |
| - cve_id                   |                +----------------------+
| - description              |
| - severity                 |
| - published_date           |
|                            |
| FixedVulnerability         |
| - cve_id                   |
+----------------------------+
            |
            v
+----------------------------+
|         Serializers        |
+----------------------------+
| VulnerabilitySerializer    |
| FixedVulnerabilitySerializer|
+----------------------------+
            |
            v
+----------------------------+
|            Views           |
|          (ViewSets)        |
+----------------------------+
| VulnerabilityViewSet       |
| FixedVulnerabilityViewSet  |
| FilteredVulnerabilityViewSet|
| VulnerabilitySummaryViewSet|
+----------------------------+
            |
            v
+----------------------------+
|           Auth             |
+----------------------------+
|    JWT Authentication      |
|  (TokenObtainPairView)     |
|   +--------------------+   |
|   |    /api/token/    |   |
|   +--------------------+   |
+----------------------------+
            |
            v
+----------------------------+
|            URLs            |
+----------------------------+
| /vulnerabilities/          |
| /fixed/                    |
| /filtered-vulnerabilities/ |
| /summary/                  |
| /api/token/                |
+----------------------------+

