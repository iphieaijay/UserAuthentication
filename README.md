<h1>UserAuthentication API</h1><br/>
Welcome to the UserAuthentication API, a robust and scalable authentication system developed with the latest .NET 8 framework. This RESTful API is designed to manage user accounts, provide secure authentication and authorization, and support essential account-related features. Built with Entity Framework Core, Identity, JWT, and SQL Server, this project is an excellent solution for modern application authentication needs.

<h3>Features</h3>
The API includes the following features:

<h4>User Management</h4>
<h5>Register:</h5> Allows users to create an account by providing their details, including email and password.
<h5>Login:</h5> Authenticates users with their credentials and returns access and refresh tokens for secure session management.
<h5>Get By ID:</h5> Retrieves user information by their unique identifier.
<h5>Get By Email:</h5> Fetches user details using their email address.<br/>
<h3>Token Management</h3>
<h4>a. JWT Authentication:</h4> Implements token-based authentication for secure communication.
<h4>b. Revoke Refresh Token:</h4> Invalidates a user's refresh token to prevent unauthorized access.
<br/>
<h3>User Actions</h3>
<h4>a. Get Current User:</h4> Fetches the currently authenticated user's details.
<h4>b. Confirm Email:</h4> Verifies a user's email address for added security.
<h4>c. Reset Password:</h4> Enables users to reset their passwords securely.
<h3>Technologies Used</h3>
.NET 8: The latest version of Microsoft's powerful framework for building scalable APIs.
Entity Framework Core: For database interactions and migrations.
ASP.NET Core Identity: For user management and authentication.
JWT (JSON Web Tokens): For secure and stateless authentication.
SQL Server: As the database provider for reliable data storage.
<h3>Project Structure</h3>
The project follows a clean architecture for scalability and maintainability:

Controllers: Handle HTTP requests and define API endpoints.
Services: Contain business logic for user management and authentication.
Repositories: Responsible for database operations using EF Core.
Models: Define the data structures for the application.
Middleware: Manage custom authentication and error handling logic.
<h3>Endpoints</h3>
HTTP Method	Endpoint	Description
POST	/api/auth/register	Registers a new user.
POST	/api/auth/login	Logs in a user.
GET	/api/users/{id}	Retrieves a user by ID.
GET	/api/users/email/{email}	Fetches a user by email.
POST	/api/auth/revoke-token	Revokes a user's refresh token.
GET	/api/auth/current-user	Gets the current logged-in user.
POST	/api/auth/confirm-email	Confirms a user's email.
POST	/api/auth/reset-password	Resets a user's password.
Setup and Installation
Prerequisites
.NET 8 SDK
SQL Server
A tool like Postman for testing API endpoints
Steps
Clone the repository:
bash
Copy code
git clone https://github.com/YourUsername/UserAuthentication.git
cd UserAuthentication
Configure the connection string in appsettings.json:
json
Copy code
"ConnectionStrings": {
    "DefaultConnection": "Server=YOUR_SERVER;Database=UserAuthenticationDb;Trusted_Connection=True;"
}
Apply migrations:
bash
Copy code
dotnet ef database update
Run the application:
bash
Copy code
dotnet run
Usage
Use a tool like Postman or Swagger to test the API endpoints.
For authentication, use the JWT token provided upon login for authorized endpoints.
Future Enhancements
Add Two-Factor Authentication (2FA) for enhanced security.
Implement social login options (e.g., Google, Facebook).
Add user roles and permission-based authorization.
Include advanced logging and monitoring.
Contributing
Contributions are welcome! Feel free to open issues or submit pull requests to enhance the project.

License
This project is licensed under the MIT License.

Contact
For inquiries or support, feel free to contact me:

Email: your-email@example.com
LinkedIn: Your LinkedIn Profile
GitHub: Your GitHub Profile
