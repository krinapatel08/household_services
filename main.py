import os
from flask import Flask, abort, render_template, request, redirect, flash, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns

curr_dir = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///homerenovation.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "letsencrypt"
app.config['PASSWORD_HASH']='sha512'

app.config['UPLOAD_EXTENSIONS'] = ['.pdf']
app.config['UPLOAD_PATH'] = os.path.join(curr_dir, 'static', "pdfs")

db = SQLAlchemy()
db.init_app(app)
app.app_context().push()

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=True)
    address = db.Column(db.String(80), unique=True)
    pincode = db.Column(db.Integer, unique=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_contractor = db.Column(db.Boolean, default=False)
    is_homeowner = db.Column(db.Boolean, default=False)
    is_app = db.Column(db.Boolean, default=False)
    avg_rating = db.Column(db.Float, default=0.0)
    rating_Count = db.Column(db.Integer, default=0)
    con_file = db.Column(db.String(80), nullable=True)
    con_experience = db.Column(db.String(80), nullable=True)
    service_id = db.Column(db.Integer, db.ForeignKey('renovation_services.id', ondelete="SET NULL"), nullable=True)

    service = db.relationship('RenovationServices', back_populates="contractors")
    homeowner_request = db.relationship('RenovationServiceRequest', back_populates='homeowner', foreign_keys='RenovationServiceRequest.homeowner_id')
    contractor_request = db.relationship('RenovationServiceRequest', back_populates='contractor', foreign_keys='RenovationServiceRequest.contractor_id')

class RenovationServices(db.Model):
    __tablename__ = "renovation_services"
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(80), unique=True, nullable=False)
    service_description = db.Column(db.String(80), nullable=True)
    base_price = db.Column(db.Integer, nullable=True)
    time_required = db.Column(db.String(80), nullable=True)
    contractors = db.relationship('User', back_populates="service", cascade="all, delete")
    request = db.relationship('RenovationServiceRequest', back_populates="service", cascade="all, delete")

class RenovationServiceRequest(db.Model):
    __tablename__ = "renovation_service_request"
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('renovation_services.id'), nullable=True)
    homeowner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contractor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    req_type = db.Column(db.String(10), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(80), nullable=True)
    date_created = db.Column(db.Date, nullable=False, default=datetime.now().date())
    date_closed = db.Column(db.Date, nullable=True)
    rating_by_homeowner = db.Column(db.Float, default=0.0)
    review_by_homeowner = db.Column(db.String(80), nullable=True)

    service = db.relationship('RenovationServices', back_populates='request')
    homeowner = db.relationship('User', back_populates='homeowner_request', foreign_keys=[homeowner_id])
    contractor = db.relationship('User', back_populates='contractor_request', foreign_keys=[contractor_id])

def create_admin():
    with app.app_context():
        admin_user = User.query.filter_by(is_admin=True).first()
        if not admin_user:
            admin_user = User(user_name="admin", password='12345678', is_admin=True,is_app=True)
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created successfully")

with app.app_context():
    db.create_all()
    create_admin()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/rwu_admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        print(username)
        print(password)
        
        
        admin = User.query.filter_by(is_admin=True).first()
        
        if admin and admin.password == password :
            session['username'] = username
            session['is_admin'] = True
            flash('Login successful!', 'success')
            return redirect('/admin_dashboard')
    
    return render_template('admin_login.html')

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(user_name=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['is_contractor'] = user.is_contractor
            session['is_homeowner'] = user.is_homeowner
            session['username'] = user.user_name
            
            if user.is_contractor:
                user_type = "contractor"
                if user.is_app==False:
                    flash('Please wait for admin approval', 'danger')
                    return redirect('/login')
                if user.service_id==None:
                    flash('Your service is not available now, please create a new account with another service', 'danger')
                    return redirect('/login')
                return redirect('/' + user_type + '_dashboard')
            
            if user.is_homeowner:
                user_type = "homeowner"
                flash('Login successful', 'success')
                return redirect('/' + user_type + '_dashboard')
        
        flash('Login unsuccessful, please check username and password', 'danger')
    return render_template('login.html')

@app.route("/contractor_register", methods=["GET", "POST"])
def contractor_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        address = request.form['address']
        pincode = request.form['pincode']
        con_file = request.files['con_file']
        con_experience = request.form['con_experience']
        service = request.form['service']
        # service_id = RenovationServices.query.filter_by(service_name=service).first().id
        user = User.query.filter_by(user_name=username).first()
        
        if user:
            flash('User already exists. Please choose a different username', 'danger')
            return redirect('/contractor_register')

        file_name = secure_filename(con_file.filename)
        if file_name != "":
            file_ext = os.path.splitext(file_name)[1]
            renamed_file_name = username + file_ext
            
            if file_ext not in app.config['UPLOAD_EXTENSIONS']:
                abort(400)
            
            con_file.save(os.path.join(app.config['UPLOAD_PATH'], renamed_file_name))
            user = User(
                user_name=username,
                password=generate_password_hash(password),
                is_contractor=True,
                address=address,
                pincode=pincode,
                con_file=renamed_file_name, 
                con_experience=con_experience,
                # service_id=service_id
            )
            db.session.add(user)
            db.session.commit()
            flash('Registration successful, please login', 'success')
            return redirect('/login')
    
    services = RenovationServices.query.all()
    return render_template('contractor_register.html', services=services)

@app.route("/homeowner_register", methods=["GET", "POST"])
def homeowner_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        address = request.form['address']
        pincode = request.form['pincode']
        user = User.query.filter_by(user_name=username).first()
        
        if user:
            flash('User already exists. Please choose a different username', 'danger')
            return redirect('/homeowner_register')
        
        user = User(
            user_name=username,
            password=generate_password_hash(password),
            is_homeowner=True,
            is_app=True,
            address=address,
            pincode=pincode
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful, please login', 'success')
        return redirect('/login')
    
    return render_template('homeowner_register.html')

@app.route("/logout")
def logout():
    session.pop('username', None)
    session.pop('is_admin', None)
    session.pop('is_contractor', None)
    session.pop('is_homeowner', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))



@app.route("/admin_dashbord",methods=["GET","POST"])
def admin_dashboard():
    if not session.get('is_admin'):
        flash('please login first','danger')
        return redirect('/login')
    services=RenovationServices.query.all()
    requests = RenovationServiceRequest.query.all()
    unapproved_contractors=User.query.filter_by(is_contractor=True,is_app=False).all()
    return render_template('admin_dashboard.html',unapproved_contractors=unapproved_contractors,services=services,requests=requests,admin_name=session['username'])

@app.route("/admin_dashboard/create_service",methods=["GET","POST"])
def create_service():
    if not session.get('is_admin'):
        flash('please login first','danger')
        return redirect('/login')
    if request.method=="POST":
        service_name=request.form['service_name']
        service_description=request.form['service_description']
        base_price=request.form['base_price']
        time_required=request.form['time_required']
        new_services=RenovationServices(service_name=service_name,service_description=service_description,base_price=base_price ,time_required=time_required)
        db.session.add(new_services)
        db.session.commit()
        flash('service created successfully','success')
        return redirect('/admin_dashbord')
    return render_template('create_service.html')

@app.route("/admin_dashboard/edit_service/<int:service_id>",methods=["GET","POST"])
def edit_service(service_id):
    if not session.get('is_admin'):
        flash('please login first','danger')
        return redirect('/login')
    service=RenovationServices.query.get_or_404(service_id)
    if request.method=="POST":
        service.service_name=request.form['service_name']
        service.service_description=request.form['service_description']
        service.base_price=request.form['base_price']
        service.time_required=request.form['time_required']
        db.session.commit()
        flash('service updated successfully','success')
        return redirect('/admin_dashbord')
    return render_template('edit_service.html',service=service)

@app.route("/admin_dashboard/delete_service/<int:service_id>",methods=["GET","POST"])
def delete_service(service_id):
    if not session.get('is_admin'):
        flash('please login first','danger')
        return redirect('/login')
    service=RenovationServices.query.get_or_404(service_id)
    approved_contractors=User.query.filter_by(is_contractor=True,is_app=True,session_id=service_id).all()
    for contractor in approved_contractors:
        contractor.is_app=False
    db.session.delete(service)
    db.session.commit()
    flash('service deleted successfully','success')
    return redirect('/admin_dashbord')


@app.route("/admin_dashboard/view_contractor/<int:contractor_id>", methods=["GET", "POST"])
def view_contractor(contractor_id):
    if not session.get('is_admin'):
        flash('Please login first', 'danger')
        return redirect('/login')
    
    contractor = User.query.get_or_404(contractor_id)
    return render_template('view_contractor.html', contractor=contractor)

@app.route("/admin_dashboard/approve_contractor/<int:contractor_id>", methods=["GET", "POST"])
def approve_contractor(contractor_id):
    if not session.get('is_admin'):
        flash('Please login first', 'danger')
        return redirect('/login')
    
    contractor = User.query.get_or_404(contractor_id)
    contractor.is_app=True
    db.session.commit()
    flash('contractor approved successfully','success')
    return redirect('/admin_dashbord')
   
@app.route("/admin_dashboard/reject_contractor/<int:contractor_id>", methods=["GET", "POST"])
def reject_contractor(contractor_id):
    if not session.get("is_admin"):
        flash('Please login first', 'danger')
        return redirect("/login")
    
    contractor = User.query.get_or_404(contractor_id)
    pdf_file = contractor.con_file
    
    if pdf_file:
        path_file = os.path.join(app.config['UPLOAD_PATH'], pdf_file)
        if os.path.exists(path_file):
            try:
                os.remove(path_file)
                print('File deleted successfully')
            except Exception as e:
                print(f'Error deleting file: {e}')
        else:
            print('File not found')

    db.session.delete(contractor)
    db.session.commit()
    flash('Contractor rejected successfully', 'success')
    return redirect('/admin_dashboard')

@app.route("/contractor_dashboard", methods=["GET", "POST"])
def contractor_dashboard():
    if not session.get('is_contractor'):
        flash('please login first','danger')
        return redirect('/login')
    cid= User.query.filter_by(user_name=session['username']).first().id
    contractor=User.query.filter_by(id=cid).first()
    if contractor.is_app==False:
        flash("please wait for admin approval",'danger')
        return redirect('/login')
    pending_requests=RenovationServiceRequest.query.filter_by(contractor_id=cid,status="Pending",req_type='private').all()
    accepted_requests=RenovationServiceRequest.query.filter_by(contractor_id=cid,status="accepted").all()
    Closed_requests=RenovationServiceRequest.query.filter_by(contractor_id=cid,status="closed").all()
    return render_template('contractor_dashboard.html',pending_requests=pending_requests,accepted_requests=accepted_requests,Closed_requests= Closed_requests)


@app.route('/homeowner_dashboard', methods=["GET", "POST"])
def homeowner_dashboard():
    if not session.get('is_homeowner'):
        flash('Please login first', 'danger')
        return redirect("/login")
    
    homeowner = User.query.filter_by(user_name=session["username"]).first()
    services = RenovationServices.query.join(User).filter(User.is_app == True).all()
    service_history = RenovationServiceRequest.query.filter_by(homeowner_id=homeowner.id).filter(RenovationServiceRequest.contractor)
    
    return render_template('homeowner_dashboard.html', services=services, service_history=service_history)

@app.route('/homeowner_dashboard/create_request/<int:service_id>', methods=["GET", "POST"])
def create_request(service_id):
    if not session.get('is_homeowner'):
        flash('Please login first', 'danger')
        return redirect("/login")
    homeowner=User.query.filter_by(user_name=session["username"]).first()
    if request.method == "POST":
        contractor = request.form.get('contractor')
        description = request.form.get('description')
        cid = User.query.filter_by(user_name=contractor).first().id
        homeowner = User.query.filter_by(user_name=session["username"]).first()
        
        service_request = RenovationServiceRequest(
            homeowner_id=homeowner.id,
            contractor_id=cid,
            service_id=service_id,
            description=description,
            status='pending'
        )

        db.session.add(service_request)
        db.session.commit()
        flash('Request created successfully', 'success')
        return redirect("/homeowner_dashboard")

    service = RenovationServices.query.get_or_404(service_id)
    contractors = User.query.filter_by(is_contractor=True, is_app=True, service_id=service.id).all()
    return render_template('create_request.html', service=service, contractors=contractors)

@app.route('/homeowner_dashboard/edit_request/<int:service_request_id>', methods=["GET", "POST"])
def edit_request(service_request_id):
    if not session.get('is_homeowner'):
        flash('Please login first', 'danger')
        return redirect('/login')
    
    service_request = RenovationServiceRequest.query.get_or_404(service_request_id)
    
    if request.method == 'POST':
        description = request.form.get('description')
        service_request.description = description
        db.session.commit()
        flash('Request updated successfully', 'success')
        return redirect('/homeowner_dashboard')
    
    return render_template('edit_request.html', service_request=service_request)


@app.route('/homeowner_dashboard/delete_request/<int:service_request_id>', methods=["GET"])
def delete_request(service_request_id):
    if not session.get('is_homeowner'):
        flash('Please login first', 'danger')
        return redirect('/login')
    
    service_request = RenovationServiceRequest.query.get_or_404(service_request_id)
    db.session.delete(service_request)
    db.session.commit()
    flash('Request deleted successfully', 'success')
    return redirect('/homeowner_dashboard')


@app.route('/homeowner_dashboard/search')
def homeowner_search():
    if not session.get('is_homeowner'):
        flash('Please login first', 'danger')
        return redirect('/login')
    
    search_type = request.args.get('search_type')
    search_query = request.args.get('search_query')
    
    services = []
    
    if search_query:
        if search_type == "pincode":
            services = RenovationServices.query.join(User).filter(
                User.is_app == True,
                User.pincode.like(f'%{search_query}%')
            ).all()
        elif search_type == "service_name":
            services = RenovationServices.query.filter(
                RenovationServices.service_name.like(f'%{search_query}%')
            ).all()
        elif search_type == "address":
            services = RenovationServices.query.join(User).filter(
                User.is_app == True,
                User.address.like(f'%{search_query}%')
            ).all()
        else:
            services = RenovationServices.query.join(User).filter(
                User.is_app == True
            ).all()
    else:
        services = RenovationServices.query.join(User).filter(
            User.is_app == True
        ).all()
    
    return render_template("homeowner_search.html", services=services, homeowner_name=session.get('username'))

@app.route('/homeowner_dashboard/contractor_profile/<int:contractor_id>')
def contractor_profile(contractor_id):
    if not session.get('is_homeowner'):
        flash('Please login first', 'danger')
        return redirect('/login')
    
    new_contractor = User.query.get(contractor_id)
    reviews = RenovationServiceRequest.query.filter_by(contractor_id=contractor_id, status='closed').all()
    
    return render_template("contractor_profile.html", new_contractor=new_contractor, reviews=reviews, homeowner_name=session.get('username'))

@app.route('/contractor_dashboard/accept_request/<int:request_id>')
def accept_request(request_id):
    if not session.get('is_contractor'):
        flash('Please login first', 'danger')
        return redirect('/login')
    
    service_request = RenovationServiceRequest.query.get(request_id)
    if service_request:
        service_request.status = "accepted"
        db.session.commit()
        flash('Request accepted successfully.', 'success')
    else:
        flash('Request not found.', 'danger')
    
    return redirect('/contractor_dashboard')

@app.route('/contractor_dashboard/reject_request/<int:request_id>')
def reject_request(request_id):
    if not session.get('is_contractor'):
        flash('Please login first', 'danger')
        return redirect('/login')
    
    service_request = RenovationServiceRequest.query.get(request_id)
    
    service_request.status = "rejected"
    db.session.commit()
    flash('Request rejected successfully.', 'success')
    return redirect('/contractor_dashboard')

@app.route('/homeowner_dashboard/close_request/<int:request_id>', methods=['GET', 'POST'])
def close_request(request_id):
    if not session.get('is_homeowner'):
        flash('Please login first', 'danger')
        return redirect('/login')
    
    service_request = RenovationServiceRequest.query.get(request_id)
    if not service_request:
        flash('Request not found', 'danger')
        return redirect('/homeowner_dashboard')

    if request.method == 'POST':
        review = request.form.get('review')
        rating = request.form.get('rating')

        service_request.status = "closed"
        service_request.rating_by_homeowner = int(rating)
        service_request.review_by_homeowner = review
        service_request.date_closed = datetime.now().date()

        # Update contractor's review metrics
        contractor = User.query.get(service_request.contractor_id)
        if contractor:
            temp_rating_count = contractor.rating_count
            contractor.rating_count += 1
            contractor.avg_rating = ((contractor.avg_rating * temp_rating_count) + int(rating)) / (contractor.rating_count)

        db.session.commit()
        flash('Request closed successfully.', 'success')
        return redirect('/homeowner_dashboard')
    contractor_name = service_request.contractor.username
    service_name = service_request.service.service_name

    return render_template('rating_reviews.html', contractor=contractor_name, service=service_name, request_id=request_id, homeowner_name=session.get('username'))

@app.route('/homeowner_dashboard/create_open_pool_request/<int:service_id>', methods=["GET"])
def create_open_pool_request(service_id):
    if not session.get('is_homeowner'):
        flash('Please login first', 'danger')
        return redirect('/login')
    
    homeowner_id = User.query.filter_by(username=session.get("username")).first().id
    new_request = RenovationServiceRequest(homeowner_id=homeowner_id, service_id=service_id, req_type="public", status="pending")
    
    db.session.add(new_request)
    db.session.commit()
    flash('Request sent successfully to all contractors of this service.', 'success')
    
    return redirect('/homeowner_dashboard')


@app.route('/contractor_dashboard/open_requests', methods=['GET', 'POST'])
def open_requests():
    if not session.get('is_contractor'):
        flash("Please login first", 'danger')
        return redirect('/login')
    
    contractor = User.query.filter_by(username=session.get("username")).first()
    new_requests = RenovationServiceRequest.query.filter_by(status="pending", req_type='public', service_id=contractor.id).all()
    
    return render_template('open_requests_contractor.html', new_requests=new_requests)


@app.route('/contractor_dashboard/bid_request/<int:request_id>', methods=['GET', 'POST'])
def bid_request(request_id):
    if not session.get('is_contractor'):
        flash('Please login first', 'danger')
        return redirect('/login')
    
    if request.method == 'POST':
        description = request.form.get('description')
        contractor_id = User.query.filter_by(username=session.get('username')).first().id
        service_id = User.query.filter_by(id=contractor_id).first().service_id
        homeowner_id = RenovationServiceRequest.query.filter_by(id=request_id).first().homeowner_id
        
        new_request = RenovationServiceRequest(homeowner_id=homeowner_id, contractor_id=contractor_id, service_id=service_id, description=description)
        
        db.session.add(new_request)
        db.session.commit()
        
        flash("Bid request sent successfully.", "success")
        return redirect('/contractor_dashboard')
   
   
@app.route('/homeowner_dashboard/bidding_requests',methods=["GET","POST"])
def bidding_requests():
    if not session['is_homeowner']:
        flash('Please login first', 'danger')
        return redirect('/login')
    homeowner_id=User.query.filter_by(user_name=session['username']).first().id
    new_requests=RenovationServiceRequest.query.filter_by(status="padding",req_type="public",homeowner_id=homeowner_id).filter(RenovationServiceRequest.contractor_id.is_not(None)).all()
    return render_template('open_requests_homeowner.html',new_requests=new_requests)   

@app.route('/homeowner_dashboard/reject_request/<int:request_id>', methods=['GET', 'POST'])
def reject_requests_homeowner(request_id):
    if not session.get('is_homeowner'):
        flash('Please login first', 'danger')
        return redirect('/login')
    new_request=RenovationServiceRequest.query.filter_by(id=request_id).first()
    db.session.delete(new_request)
    db.session.commit()
    flash("Request rejected and deleted successfully", "success")
    return redirect('/homeowner_dashboard')

@app.route('/homeowner_dashboard/accept_request/<int:request_id>', methods=['GET', 'POST'])
def accept_request_homeowner(request_id):
    if not session.get('is_homeowner'):
        flash("Please login first", "danger")
        return redirect("/login")
    
    new_request = RenovationServiceRequest.query.filter_by(id=request_id).first()
    new_request.status = "accepted"
    
    old_requests = RenovationServiceRequest.query.filter_by(
        homeowner_id=new_request.homeowner_id, 
        req_type="public", 
        service_id=new_request.service_id, 
        status="pending"
    ).all()
    
    for old_request in old_requests:
        db.session.delete(old_request)
    
    db.session.commit()
    flash("Request accepted successfully", "success")
    return redirect("/homeowner_dashboard")

@app.route('/contractor_dashboard/search')
def contractor_search():
    if not session.get('is_contractor'):
        flash("Please login first", "danger")
        return redirect("/login")
    
    contractor = User.query.filter_by(user_name=session["username"]).first()
    search_type = request.args.get('search_type')
    search_query = request.args.get('search_query')
    onclause = RenovationServiceRequest.homeowner_id == User.id
    
    if search_query:
        if search_type == "pincode":
            service_request = RenovationServiceRequest.query.join(User, onclause).filter(
                User.is_homeowner == True,
                User.pincode.like(f"%{search_query}%"),
                RenovationServiceRequest.req_type == 'public',
                RenovationServiceRequest.status == 'pending',
                RenovationServiceRequest.contractor_id == None,
                RenovationServiceRequest.service_id == contractor.service_id
            ).all()
        elif search_type == "address":
            service_request = RenovationServiceRequest.query.join(User, onclause).filter(
                User.is_homeowner == True,
                User.address.like(f"%{search_query}%"),
                RenovationServiceRequest.req_type == 'public',
                RenovationServiceRequest.status == 'pending',
                RenovationServiceRequest.contractor_id == None,
                RenovationServiceRequest.service_id == contractor.service_id
            ).all()
        else:
            service_request = RenovationServiceRequest.query.join(User, onclause).filter(
                User.is_homeowner == True,
                RenovationServiceRequest.req_type == 'public',
                RenovationServiceRequest.status == 'pending',
                RenovationServiceRequest.contractor_id == None,
                RenovationServiceRequest.service_id == contractor.service_id
            ).all()
    
    return render_template('contractor_search.html', service_requests=service_request, contractor_name=session['username'])

# Route for the admin summary
@app.route('/admin_dashboard/summary')
def admin_summary():
    if not session.get("is_admin"):
        flash('Please login first', "danger")
        return redirect('/login')

    homeowner_count = User.query.filter_by(is_homeowner=True).count()
    contractor_count = User.query.filter_by(is_contractor=True).count()
    accepted_count = RenovationServiceRequest.query.filter_by(status='accepted').count()
    rejected_count = RenovationServiceRequest.query.filter_by(status='rejected').count()
    closed_count = RenovationServiceRequest.query.filter_by(status='closed').count()
    pending_count = RenovationServiceRequest.query.filter_by(status='pending').count()
    
    img_1 = os.path.join(curr_dir, 'static', 'images', 'img_1.png')
    img_2 = os.path.join(curr_dir, 'static', 'images', 'img_2.png')

# Data for roles and counts
    roles = ['Homeowners', 'Contractors']
    counts = [homeowner_count, contractor_count]
    
    plt.clf()  # Clear existing plot
    plt.figure(figsize=(6, 4))
    sns.barplot(x=roles, y=counts)
    plt.title("Number of users by role")
    plt.xlabel("User Role")
    plt.ylabel("Count")
    plt.savefig(img_1, format='png')

    status = ['Accepted', 'Rejected', 'Closed', 'Pending']
    counts = [accepted_count, rejected_count, closed_count, pending_count]
    colors = ['#ACAF5E', '#AF4436', '#9E49F4', '#FFC107']

    plt.clf()  # Clear existing plot
    plt.figure(figsize=(6, 4))
    plt.pie(counts, labels=status, colors=colors, autopct='%1.1f%%')
    plt.title("Request Status Distribution")
    plt.savefig(img_2, format='png')

    return render_template(
        'admin_summary.html',
        homeowner_count=homeowner_count,
        contractor_count=contractor_count,
        accepted_count=accepted_count,
        rejected_count=rejected_count,
        closed_count=closed_count,
        pending_count=pending_count
    )
@app.route('/admin_dashboard/search')
def admin_search():
    if not session.get('is_admin'):
        flash('Please login first', 'danger')
        return redirect('/reu_login')

    search_type = request.args.get('search_type')
    search_query = request.args.get('search_query')

    if search_query:
        if search_type == 'user':
            users = User.query.filter(User.username.like(f'%{search_query}%')).all()
            return render_template("admin_search.html", users=users, admin_name=session['username'])

        elif search_type == 'service':
            services = RenovationServices.query.filter(RenovationServices.service_name.like(f'%{search_query}%')).all()
            return render_template("admin_search.html", services=services, admin_name=session['username'])
    
    users = User.query.filter(User.is_approved == True).all()
    services = RenovationServices.query.all()
    
    return render_template("admin_search.html", users=users, admin_name=session['username'], services=services)

    
    

       

if __name__ == "__main__":
    app.run(debug=True)
