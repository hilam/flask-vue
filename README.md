:exclamation:*this appication is dependent by Python3.6,to make sure installed python3.6.*

---

+ ## What`s this?
> + Flask-vue is a solution for project which uses flask and vue.
> + You also can use the flask module or vue module in your project.

+ ## What thing does it provide?
> + Flask-vue is just a frame to help you build a webapp quickly. 
> + Flask-vue(1.0) just provides 'register','login' and so on. 
> + All suported can be found in flask and vue.

+ ## How does backend communicate with frontend?
> + There are two tokens generated by pyjwt.&nbsp;&nbsp;Backend uses the access_token and refresh_token to ensure that the user is vaild.
> + There is the module to generate token,[click to see](https://github.com/xiongsyao/flask-vue/blob/master/utils/auth_token.py)
> + is new to jwt? [click there to see more in pyjwt](http://pyjwt.readthedocs.io/en/latest/)

## Run the appication
### 1. clone the project
run `git clone https://github.com/xiongsyao/flask-vue.git`
### 2. create virtualenv
+ run `cd flask-vue`
+ run `pip install virtualenv`
+ run `virtualenv vnev`
+ if you use <b>linux</b> run `source venv/bin/activate`, <b>windows</b> run `venv\Scripts\activate`
### 3. install the requirements
run `pip install -r requirements.txt`
### 4. change the db url
you should replace SQLALCHEMY_DATABASE_URI by your DB url in the [config/dev.json](https://github.com/xiongsyao/flask-vue/blob/master/config/dev.json), and your db url should to be:  
```"postgresql://username:password@localhost/mydatabase"```  
or  ```"mysql+mysqlconnector://username:password@localhost/mydatabase"```  
or  ```"sqlite:///your.db"```
### 5. create db
+ run `python manage.py create_db`
+ run `python manage.py db upgrade`
### 6. run application
run `python manage.py runserver`  

---

## todo
+ [ ] front-end

