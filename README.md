# Access Control System for Small Organizations
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54) ![JavaScript](https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&logo=javascript&logoColor=%23F7DF1E) ![Bootstrap](https://img.shields.io/badge/bootstrap-%238511FA.svg?style=for-the-badge&logo=bootstrap&logoColor=white) ![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white)

Information Assurance Finals project by:
- Carl Cyruz Leonador
- Rolando Periña

## Project Overview
The project implements a prototype of an access control system designed for small organizations.
The system is built as a web application using Python and Flask, demonstrating key features such as user authentication, role-based access control, and basic identity management.
The web application uses HTML Jinja2 templates, and Bootstrap5 for styling.

The system makes use of a MySQL database to store user information. Security measures were implemented to keep the application secure from malicious actors.

Additional features implemented include: Password Policies, Audit Logging, Advanced RBAC, User Activity Monitoring, and Automated Backup System.

## Setup Instructions
1. **Clone this GitHub repository.**
```sh
git clone https://github.com/carl-leonador03/InfoAssurance-Finals.git
```
2. **Navigate to the Project Directory.**
```sh
cd InfoAssurance-Finals.git
```
3. **Install the required dependencies:**
It is recommended to do this inside a virtual environment, most especially on Linux clients.
```sh
pip install -r requirements.txt
```
4. **Configure the database:**
Open the `db.ini` file and enter your MySQL credentials.
```ini
[database-config]
SECRET_KEY = your_secret_key

[mysql-config]
MYSQL_DB = acs_db    ; change this if you prefer a different name for the database schema included.
MYSQL_HOST = localhost
MYSQL_USER = your_username
MYSQL_PASSWORD = your_password
MYSQL_CURSORCLASS = DictCursor
```
5. **Start MySQL Database server:**
Launch XAMPP (or your preferred MySQL or MariaDB server client). Make sure to import the schema database afterwards.
6. **Run the web application:**
Start the Flask application by executing the following command:
```sh
python app.py
```

The application will now be accessible by visiting http://localhost:8080/.
