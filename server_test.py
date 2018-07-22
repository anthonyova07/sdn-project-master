####    Elementos necesarios para la comunicacion de la intranet con el controller
######### LIBRERIAS #################
from flask import Flask, render_template, redirect, url_for, request
import requests
from pprint import pprint
import sqlite3
from db import dbaccess,timer
import json


# create the application object
app = Flask(__name__)

# Global variable
success_string=""
sdnController=""

#AGREGAR SOLICITUDES DE ACCESO 
@app.route('/server_add', methods=['GET','POST'])
def serverAdd(): ## funcion de adicionamiento de solicitudes al controlador 
    error =None ### agregar un condicional para validar la aprobacion de la solicitud 
    global sdnController ### En caso de de que sea aprobada si y solo si es enviada al C
    if request.method == 'GET':
        items = dbaccess.getServertable()  ## RECIBIR LA TABLA DE SOLICITUDES DE ACCESO DE LA BD
        return render_template('server_add.html',items=items)

    if request.method == 'POST':
        internal_ip = str(request.form['internal'])  ## userid
        external_ip = str(request.form['external']) ## urlaccess
        authServer_ip = str(request.form['authentication']) ## initial_date
        internal_mac = str(request.form['internal_mac']) ## final_date
        external_mac = str(request.form['external_mac']) ## reason
        dbaccess.insertServertable(internal_ip,external_ip,authServer_ip,internal_mac,external_mac)
        items = dbaccess.getServertable() 
    data = {'user_name':user_dict['name'], 'ip_address':user_dict['ip_addr'],'policy_type':user_dict['user_group']}
        
        server_config = dbaccess.getServerconfig() ## Solicitudes realizadas
        sdnController = server_config['sdnController_ip']
        url = 'http://'+sdnController+':6633/serverconfig'
        del(server_config['sdnController_ip'])
###############	IF DE APRROBACION	#########################
        sendConfig(server_config,url)  ### Envio de solicitud aprobada al controlador
##################################################################
        return render_template('server_add.html',items=items)

    return render_template('server_add.html')

# Sends configuration data to the controller
def sendConfig(data,url):  ## EN EL ARGUMENTO DATA ESTAN EL PUERTO ACTUAL AL CUAL SE VA ENVIAR
    data_json = json.dumps(data)
    print ('JSON being sent - ', data_json)
    print ('URL - ', url)
    headers = {'Content-type': 'application/json'}
    # response = requests.post(url, data=data_json, headers=headers)
    # pprint.pprint(response.json())



# start the server with the 'run()' method
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)
