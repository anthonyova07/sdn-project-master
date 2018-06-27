#!/usr/bin/env python

from flask import Flask, render_template, request, redirect, url_for, g, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, DateField, SubmitField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from flask import Flask, render_template, request, redirect, url_for, g, flash, Response
import sqlite3
import gevent
from gevent.wsgi import WSGIServer
from gevent.queue import Queue
import time, datetime, json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask_datepicker import datepicker

import sys

app = Flask(__name__)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
file_path = os.path.abspath(os.getcwd())+"/database.db"
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+file_path
bootstrap = Bootstrap(app)
datepicker(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def dateDiffInSeconds(date1, date2):
  timedelta = date2 - date1
  return timedelta.days * 24 * 3600 + timedelta.seconds

def daysHoursMinutesSecondsFromSeconds(seconds):
	minutes, seconds = divmod(seconds, 60)
	hours, minutes = divmod(minutes, 60)
	days, hours = divmod(hours, 24)
	return (days, hours, minutes, seconds)

class DateForm(FlaskForm):
    dt = DateField('Pick a Date', format="%m/%d/%Y")

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    limited_date = db.Column(db.String(120))
    creation_date = db.Column(db.String(120))
    admin_privilege = db.Column(db.Integer)

class SecurityPolicy():
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    publisher = db.Column(db.String(120))
    description = db.Column(db.String(120))
    category = db.Column(db.String(40))
    url = db.Column(db.String(100))
    port = db.Column(db.String(6))
    created_on = db.Column(db.String(20))
    created_by = db.Column(db.String(40))

#class User(UserMixin, db.Model):
#    id = db.Column(db.Integer, primary_key=True)
#    userid = db.Column(db.Integer)
#    urlaccess = db.Column(db.String(50))
#    reason = db.Column(db.String(150))
#    limited_date = db.Column(db.String(120))
#CREATE TABLE access(
#            id INTEGER PRIMARY KEY AUTOINCREMENT, userid INTEGER NOT NULL, urlaccess TEXT NOT NULL,
#            reason TEXT NOT NULL, limited_date TEXT NOT NULL);
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
##########/

class SecurityPolicyForm(FlaskForm):
    name = StringField('Nombre', validators=[InputRequired("Ingrese un Nombre"), Length(max=100)])
    publisher = StringField('publisher', validators=[InputRequired("Ingrese un Fabricante"), Length(max=100)])
    description = StringField('description', validators=[InputRequired("Ingrese un Descripcion"), Length(max=120)])
    category = StringField('category', validators=[InputRequired("Ingrese un Categoria"), Length(max=40)])
    url = StringField('url', validators=[InputRequired("Ingrese un URL"), Length(max=100)])
    port = StringField('port', validators=[InputRequired("Ingrese un Puerto"), Length(max=6)])
    submit = SubmitField('Guardar')


DATABASE = "database.db"

# Gestión de la base de datos.

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def change_db(query,args=()):
    cur = get_db().execute(query, args)
    get_db().commit()
    cur.close()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# URL de enrutamiento y procesamientos.
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/adminpanel')
@login_required
def adminpanel():
    if current_user.admin_privilege == 1:
        user_list=query_db("SELECT * FROM user")
        #limited_date_object = datetime.datetime.strptime(current_user.limited_date, '%Y-%m-%d %H:%M:%S')
        return render_template("adminpanel.html",current_user=current_user,user_list=user_list, actualdate = datetime.datetime.now(), datetime = datetime)
    else:
        return('<h1>Su actual usuario no es administrador.</h1>')

@app.route('/policyautocomplete', methods=['GET'])
def policyautocomplete():
    search = request.args.get('qry')
    policies_list =  query_db("SELECT name FROM security_policy")
    return Response(json.dumps(policies_list), mimetype='application/json')

@app.route('/policieslist', methods=['GET', 'POST'])
@login_required
def policieslist():
    policies_list =  query_db("SELECT * FROM security_policy")
    return render_template("policieslist.html"
        , current_user = current_user
        , policies_list = policies_list)



@app.route('/policiesform', methods=['GET', 'POST'])
@login_required
def policiesform():

    form = SecurityPolicyForm()

    if request.method == "GET":
        return render_template("policiesform.html", form=form)
    elif request.method == "POST":    
        new_securityPolicy = SecurityPolicy(name = form.name.data.title()
            , publisher = form.publisher.data.title()
            , description = form.description.data
            , category = form.category.data.title()
            , url = form.url.data.lower()
            , port = form.port.data
            , created_on = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            , created_by = current_user.username)
        db.session.add(new_securityPolicy)
        db.session.commit()
        return redirect(url_for("policieslist"))
    else:
        return('<h1>Su actual usuario no es administrador.</h1>')

@app.route('/policyupdate/<int:id>', methods=['GET', 'POST'])
@login_required
def policyupdate(id):
    
    policy = SecurityPolicyForm()

    if request.method == "GET":
        policy = query_db("SELECT * FROM security_policy WHERE id=?", [id], one=True)
        return render_template("policyupdate.html", policy=policy)
    elif request.method == "POST":
        values = [policy.name.data.title() , policy.publisher.data.title(), policy.description.data, policy.category.data.title(), policy.url.data.lower(), policy.port.data, id]
        change_db("UPDATE security_policy SET name=?, publisher=?, description=?, category=?, url=?, port=? WHERE id=?", values)
        return redirect(url_for("policieslist"))

@app.route('/policydelete/<int:id>', methods=['GET', 'POST'])
@login_required
def policydelete(id):
    policy = SecurityPolicyForm()

    if request.method == "GET":
        policy = query_db("SELECT * FROM security_policy WHERE id=?", [id], one=True)
        return render_template("policydelete.html", policy=policy)
    elif request.method == "POST":
        change_db("DELETE FROM security_policy WHERE id = ?",[id])
        return redirect(url_for("policieslist"))

@app.route('/accesslist')
@login_required
def accesslist():
    if current_user.admin_privilege == 1:
        access_list=query_db("SELECT * FROM access")
        #limited_date_object = datetime.datetime.strptime(current_user.limited_date, '%Y-%m-%d %H:%M:%S')
        return render_template("accesslist.html",current_user=current_user,access_list=access_list, actualdate = datetime.datetime.now(), datetime = datetime, len=len)
    else:
        return('<h1>Su actual usuario no es administrador.</h1>')

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():

    if request.method == "GET":
        return render_template("create.html",access=None)

    if request.method == "POST":
        access=request.form.to_dict()
        values=[current_user.username,access["urlaccess"],access["initial_date"],access["limited_date"],access["reason"]]
        change_db("INSERT INTO access (userid,urlaccess,initial_date,limited_date,reason) VALUES (?,?,?,?,?)",values)

        ############ ENVIO DE CORREO ###################################################

        fromaddr = "iamtheadmin@root.com"
        toaddr = "anthonyovalles@gmail.com"
        msg = MIMEMultipart()
        msg['From'] = fromaddr
        msg['To'] = toaddr
        msg['Subject'] = "Solicitud de acceso a servicio via SDN"
        
        body = "El usuario: @@@@ , solicito el acceso para: Acceder al switch desde el 2018/06/13 XX:XX:XX hasta el 2018/06/13 XX:XX:XX "
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(toaddr, "bayovanex0705")
        text = msg.as_string()
        server.sendmail(fromaddr, toaddr, text)
        server.quit()
        ###############################################################################



        # user=request.form.to_dict()
        # values_user=[current_user.username,user["limited_date"]]
        # change_db("INSERT INTO user (limited_date) VALUES (?)",values_user)

        if current_user.admin_privilege == 1:
            return redirect(url_for("accesslist"))
        else:
            return redirect(url_for("requestdone"))

@app.route('/requestdone', methods=['GET', 'POST'])
@login_required
def requestdone():
    return render_template("requestdone.html")

@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def udpate(id):

    if request.method == "GET":
        access_list=query_db("SELECT * FROM access WHERE id=?",[id],one=True)
        return render_template("update.html",access=access_list)

    if request.method == "POST":

        print(request.form)
        access=request.form.to_dict()
        values=[access["urlaccess"],access["initial_date"], access["limited_date"],access["reason"],id]
        change_db("UPDATE access SET urlaccess=?, initial_date=?, limited_date=?, reason=? WHERE ID=?",values)
        return redirect(url_for("accesslist"))

@app.route('/userupdate/<int:id>', methods=['GET', 'POST'])
@login_required
def userudpate(id):

    if request.method == "GET":
        user=query_db("SELECT * FROM user WHERE id=?",[id],one=True)
        return render_template("userupdate.html",user=user)

    if request.method == "POST":

        print(request.form)
        user=request.form.to_dict()
        print(user)
        values=[user["username"],user["email"],user["creation_date"],user["admin_privilege"],id]
        change_db("UPDATE user SET username=?, email=?, creation_date=?, admin_privilege=? WHERE ID=?",values)
        return redirect(url_for("adminpanel"))

@app.route('/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def delete(id):

    if request.method == "GET":
        user=query_db("SELECT * FROM user WHERE id=?",[id],one=True)
        return render_template("delete.html",user=user)

    if request.method == "POST":
        change_db("DELETE FROM user WHERE id = ?",[id])
        return redirect(url_for("adminpanel"))

@app.route('/deleterequest/<int:id>', methods=['GET', 'POST'])
@login_required
def deleterequest(id):

    if request.method == "GET":
        access=query_db("SELECT * FROM access WHERE id=?",[id],one=True)
        return render_template("deleteaccess.html")

    if request.method == "POST":
        change_db("DELETE FROM access WHERE id = ?",[id])
        return redirect(url_for("accesslist"))

@app.route('/activate/<int:id>')
def activate(id):
        change_db("UPDATE user SET Activated=1 WHERE ID=?",[id])
        return redirect(url_for("adminpanel"))

@app.route('/deactivate/<int:id>')
def deactivate(id):
        change_db("UPDATE user SET Activated=0 WHERE ID=?",[id])
        return redirect(url_for("adminpanel"))

@app.route('/approverequest/<int:id>')
def approverequest(id):
        change_db("UPDATE access SET approve=1 WHERE ID=?",[id])
        return redirect(url_for("accesslist"))

@app.route('/rejectrequest/<int:id>')
def rejectrequest(id):
        change_db("UPDATE access SET approve=0 WHERE ID=?",[id])
        return redirect(url_for("accesslist"))

@app.route('/addtime/<int:id>')
def addtime(id):
        now = datetime.datetime.now()
        finalDate = now + datetime.timedelta(seconds=320)
        finalDate = "'"+ finalDate.strftime('%Y-%m-%d %H:%M:%S') +"'"
        change_db("UPDATE user SET limited_date="+ finalDate +" WHERE ID=?",[id])
        return redirect(url_for("adminpanel"))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated == True:
        return redirect(url_for("userpanel"))
    else:
        form = LoginForm()

        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                if check_password_hash(user.password, form.password.data):
                    login_user(user, remember=form.remember.data)
                    return redirect(url_for('userpanel'))
                else:
                    return render_template('login.html', form=form, error=True)
                    #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'
        return render_template('login.html', form=form, error=False)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        default_limited_date = datetime.datetime.now()
        print (default_limited_date)
        print (default_limited_date.strftime("%Y-%m-%d %H:%M:%S"))
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, creation_date = default_limited_date.strftime("%Y-%m-%d %H:%M:%S"), admin_privilege = 0 )
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created! ' + form.username.data + ' ' + form.email.data + ' ' + default_limited_date.strftime("%Y-%m-%d %H:%M:%S") + ' </h1>'

    return render_template('signup.html', form=form)

@app.route('/userpanel')
@login_required
def userpanel():
    if current_user.admin_privilege == 0: 
        return render_template('userpanel.html', user=current_user)
    else:
        return redirect(url_for('adminpanel'))

@app.route('/switch_1')
@login_required
def switch_1():
    access_to_switch = False
    if current_user.admin_privilege == 0: 
    # '0' meaning a normal user. '1' would be an admin user. '2' is an admin user with total admin privilege that can't be erased or modified.
    # a '2' level admin privilege user would sometimes be refered as 'the system'. 
        user_access_list = query_db("SELECT * FROM access WHERE userid=?",[current_user.username])
        for accessrequest in user_access_list:
            if "switch" in accessrequest["urlaccess"] and accessrequest["approve"] == 1:
               access_to_switch = True
               access_limited_date = accessrequest["limited_date"]
               access_initial_date = accessrequest["initial_date"]
               break
    else:
        return redirect(url_for('adminpanel'))

    if access_to_switch == True:
        initial_date = datetime.datetime.strptime(access_initial_date, '%Y-%m-%d %H:%M:%S')
        leaving_date = datetime.datetime.strptime(access_limited_date, '%Y-%m-%d %H:%M:%S')
        now = datetime.datetime.now()
        #dti = daysHoursMinutesSecondsFromSeconds(dateDiffInSeconds(now, initial_date))
        #dtf = daysHoursMinutesSecondsFromSeconds(dateDiffInSeconds(now, leaving_date))

        if now > initial_date and now < leaving_date:
            return render_template('switch_1.html', user=current_user)
        else:
            return render_template('no_access.html', error=2, user=current_user)
    else:
        return render_template('no_access.html', error=1, user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
