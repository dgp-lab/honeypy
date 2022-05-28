from ast import And
from pickle import FALSE
from dotenv import load_dotenv
import yagmail
import os
import padroes
import datetime
import pytz

EMPTY_FILE = 8

def valida_incidente():
    
    ###### Abre os arquivos para leitura ######
    
    load_dotenv()

    ###### PATHS para uso no editor ######

    PATH_APACHE = os.environ.get("PATH_APACHE")
    PATH_SSH = os.environ.get("PATH_SSH")
    PATH_VSFTPD = os.environ.get("PATH_VSFTPD")
    PATH_MYSQL = os.environ.get("PATH_MYSQL")

    error_flag = False

    vsftpd_file = open(PATH_VSFTPD, 'r')



    ##### Armazena os logs que serão lidos num backup. Nos originais é feito um refresh #####
       ##### Cada vez que o código executa o log é analisado e armazenado no backup #####

    report =  open("report.txt", 'w') 

############################################-APACHE-############################################

    apache_bkp =  open("access.log2", 'a')

    # Lê os logs do apache

    try:
        with open(PATH_APACHE, 'r') as apache_file:

            report.write('\n')
            report.write('<h3> *** APACHE *** </h3>')
            report.write('\n') 

            for line in apache_file:

                apache_bkp.write(line)

                # Valida tentativas de acesso

                if padroes.APACHE_PERMISSION_DENIED in line:

                    report.write('<h4>Tentativa de acesso no Apache</h4>')
                    report.write('\n')
                    report.write(line)
                    report.write('\n')

                if  padroes.APACHE_PERMISSION_OK in line and padroes.APACHE_ADMIN in line:

                    report.write('<h4>Conseguiu logar como admin no Apache</h4>')
                    report.write('\n')
                    report.write(line)
                    report.write('\n')

                if padroes.APACHE_QUERY in line:

                    report.write('<h4>Busca no campo efetuada</h4>')
                    report.write('\n')
                    report.write(line)
                    report.write('\n')

                # Valida SQL Injection
                if padroes.APACHE_EQ in line and ( padroes.APACHE_SINGLE in line or padroes.APACHE_DOUBLE in line ):

                    report.write('<h4>Possível SQL Injection</h4>')
                    report.write('\n')
                    report.write(line)
                    report.write('\n')

                # Valida Cross-site Scripting (XSS)
                if padroes.APACHE_XSS in line:

                    report.write('<h4>Possível XSS</h4>')
                    report.write('\n')
                    report.write(line)
                    report.write('\n') 

    except OSError as e:
        error_flag = True  
    

############################################-Vsftpd-############################################

    vsftpd_bkp =  open("vsftpd.log2", 'a')

    # Lê os logs do vsftpd
    try:
        with open(PATH_SSH, 'r') as ssh_file:
            report.write('\n')
            report.write('<h3>*** VSFTPD ***</h3>')
            report.write('\n')
            for line in vsftpd_file:
                vsftpd_bkp.write(line)
                if padroes.VSFTPD_ACCEPTED_LOGIN in line:
                    report.write('<h4>Logou no FTP!</h4>')
                    report.write('\n')
                    report.write(line)
                    report.write('\n') 
                if padroes.VSFTPD_FAILED_LOGIN in line:
                    report.write('<h4>Login inválido</h4>')
                    report.write('\n')
                    report.write(line)
                    report.write('\n') 
                if padroes.VSFTPD_COMMAND in line:
                    report.write('<h4>Comando executado</h4>')
                    report.write('\n')
                    report.write(line)
                    report.write('\n')

        # Dar refresh no log original do vsftpd
    except OSError as e:
        error_flag = True
    

############################################-MySQL-############################################

    mysql_bkp =  open("query.log2", 'a')

    # Lê os logs do mysql
    try:
        with open(PATH_MYSQL, 'r') as mysql_file:
            report.write('\n')
            report.write('<h3>*** MySQL ***</h3>')
            report.write('\n')
            for line in mysql_file:
                mysql_bkp.write(line)
                if padroes.MYSQL_CONNECT in line:

                    report.write('<h4>Tentativa de conexão</h4>')
                    report.write('\n')
                    report.write(line)
                    report.write('\n') 

                if padroes.MYSQL_QUERY in line:

                    report.write('<h4>Query realizada</h4>')
                    report.write('\n')
                    report.write(line)
                    report.write('\n') 

        # Dar refresh no log original do Mysql
    except OSError as e:
            error_flag = True


############################################-SSH-############################################
 
    ssh_bkp =  open("auth.log2", 'a')

    # Lê os logs do ssh
    try:
        with open(PATH_SSH, 'r') as ssh_file:
            report.write('\n')
            report.write('<h3>*** SSH ***</h3>')
            report.write('\n')
            for line in ssh_file:
                ssh_bkp.write(line)
                if padroes.SSH_ACCEPTED_LOGIN in line:

                    report.write('<h4>Logou no SSH!</h4>')
                    report.write('\n')
                    report.write(line)
                    report.write('\n')
       # Valida tentativas de acesso
                if padroes.SSH_FAILED_LOGIN in line:

                    report.write('<h4>Tentativa de acesso</h4>')
                    report.write('\n')
                    report.write(line)
                    report.write('\n')

                if padroes.SSH_INVALID_USER in line:

                    report.write('<h4>Usuário inválido</h4>')
                    report.write('\n')
                    report.write(line)
                    report.write('\n')
                    
        # Dar refresh no log original do ssh
    except OSError as e:
        error_flag = True

        
    #Limpa os logs originais, para que os alertas não se repitam na próxima execução

    if error_flag == False:

        apache_file = open(PATH_APACHE, 'w')
        ssh_file = open(PATH_SSH, 'w')
        vsftpd_file = open(PATH_VSFTPD, 'w')
        mysql_file = open(PATH_MYSQL, 'w')

        apache_file.write('')
        ssh_file.write('')
        vsftpd_file.write('')
        mysql_file.write('')

        apache_file.close()
        ssh_file.close()
        vsftpd_file.close()
        mysql_file.close()
        
    report.close()
    apache_bkp.close()
    ssh_bkp.close()
    vsftpd_bkp.close()
    mysql_bkp.close()



def envia_mail():

    load_dotenv()
    EMAIL = os.environ.get("EMAIL")
    TOKEN = os.environ.get("TOKEN")
    yag = yagmail.SMTP(EMAIL, TOKEN)

    try:
        with open('report.txt','r') as report:
            if ( len(report.readlines()) != EMPTY_FILE ):
                local_tz = pytz.timezone('America/Sao_Paulo')
                titulo = 'Report - ' + str(datetime.datetime.now(local_tz))
                file = open('report.txt','r')
                yag.send(EMAIL,titulo,file.read())
    except OSError as e:
            error_flag = True
    
#---------main---------#

valida_incidente()
envia_mail()