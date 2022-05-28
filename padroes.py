
############################################-PADROES DE COMPORTAMENTO UTILIZANDO OS LOGS DO SISTEMA (LINUX)-############################################

############################################-APACHE-############################################
###-NO LOGIN E SENHA-###
APACHE_PERMISSION_DENIED='GET / HTTP/1.1" 401'
APACHE_PERMISSION_OK='"GET / HTTP/1.1" 200'
APACHE_ADMIN='admin'
###-NO CAMPO DE TEXTO-###
APACHE_QUERY='GET /result.php?username='
###-Possível SQL Injection-###
APACHE_EQ='%3D'      #=
APACHE_SINGLE='%27'   #'
APACHE_DOUBLE='%22'   #"
###-Possível XSS-###
APACHE_XSS='%3Cscript' 
#############################################-SSH-##############################################
SSH_FAILED_LOGIN='Failed password for'
SSH_INVALID_USER='Invalid user'
SSH_ACCEPTED_LOGIN='Accepted password for' 
############################################-Vsftpd-############################################
VSFTPD_ACCEPTED_LOGIN='OK LOGIN:'
VSFTPD_FAILED_LOGIN='FAIL LOGIN:'
VSFTPD_COMMAND='FTP command:'
############################################-MySQL-#############################################
MYSQL_CONNECT='Connect'
MYSQL_QUERY='Query'