# Access Control System for Small Organizations
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54) ![HTML5](https://img.shields.io/badge/html5-%23E34F26.svg?style=for-the-badge&logo=html5&logoColor=white) ![JavaScript](https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&logo=javascript&logoColor=%23F7DF1E) ![Bootstrap](https://img.shields.io/badge/bootstrap-%238511FA.svg?style=for-the-badge&logo=bootstrap&logoColor=white) ![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white) ![Jinja](https://img.shields.io/badge/jinja-white.svg?style=for-the-badge&logo=jinja&logoColor=black) ![SQLite](https://img.shields.io/badge/sqlite-%2307405e.svg?style=for-the-badge&logo=sqlite&logoColor=white)

Information Assurance Finals project by:
- Carl Cyruz Leonador
- Rolando Periña

## Project Overview
The project implements a prototype of an access control system designed for small organizations.
The system is built as a web application using Python and Flask, demonstrating key features such as user authentication, role-based access control, and basic identity management.
The web application uses HTML Jinja templates, and Bootstrap5 for styling.

The system makes use of a SQLite database to store user information. Security measures were implemented to keep the application secure from malicious actors.

Additional features implemented include: Password Policies, Audit Logging, Advanced RBAC, User Activity Monitoring, and Automated Backup System.

## Setup Instructions
1. Clone this GitHub repository.
2. Launch XAMPP (or other SQLite Database server client).
3. Import the database in the `instance` directory.
4. Install the required dependencies from the `requirements.txt` file. You can install it via:
```
pip install -r requirements.txt
```
5. Run the web application by running the `app.py` Python file.
6. Access the web application by visiting http://localhost:8080/.
