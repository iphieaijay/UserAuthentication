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
a. .NET 8: The latest version of Microsoft's powerful framework for building scalable APIs.<br/>
b. Entity Framework Core: For database interactions and migrations.<br/>
c. ASP.NET Core Identity: For user management and authentication.<br/>
d. JWT (JSON Web Tokens): For secure and stateless authentication.<br/>
e. SQL Server: As the database provider for reliable data storage.<br/>
<h3>Project Structure</h3>
The project follows a clean architecture for scalability and maintainability:

Controllers: Handle HTTP requests and define API endpoints.
Services: Contain business logic for user management and authentication.
Repositories: Responsible for database operations using EF Core.
Models: Define the data structures for the application.
Middleware: Manage custom authentication and error handling logic.
<h3>Endpoints</h3>
<table><tr><th>HTTP Method</th>	<th>Endpoint</th>	<th>Description</th></tr>
<tbody><tr><td>POST</td>	<td>/api/auth/register</td><td>	Registers a new user.</td></tr>
<tr><td>POST</td>	<td>/api/auth/login</td>	<td>Logs in a user.</td></tr>
<tr><td>GET</td><td>/api/users/{id}</td>	<td>Retrieves a user by ID.</td></tr>
<tr><td>GET</td>	<td>/api/users/email/{email}</td>	<td>Fetches a user by email.</td></tr>
<tr><td>POST</td>	<td>/api/auth/revoke-token</td>	<td>Revokes a user's refresh token.</td></tr>
<tr><td>GET</td><td>	/api/auth/current-user</td><td>	Gets the current logged-in user.</td></tr>
<tr><td>POST</td><td>	/api/auth/confirm-email</td><td>	Confirms a user's email.</td></tr>
<tr><td>POST</td>	<td>/api/auth/reset-password</td>	<td>Resets a user's password.</td></tr>
</tbody>
</table>
<h3>Setup and Installation</h3>
<h4>Prerequisites</h4>
a..NET 8 SDK
b. SQL Server
c. A tool like Postman for testing API endpoints
<h3>Steps</h3>
<h4>a. Clone the repository:</h4>
<h6>Copy code
git clone https://github.com/YourUsername/UserAuthentication.git
cd UserAuthentication</h6>
<h4>b. Configure the connection string in appsettings.json:</h4>
Using this code: 
"ConnectionStrings": {
    "DefaultConnection": "Server=YOUR_SERVER;Database=UserAuthenticationDb;Trusted_Connection=True;"
}
<h4>c. Apply migrations:</h4>
dotnet ef database update
<h4>d. Run the application:</h4>
Use this code:
dotnet run
<h4>e. Usage</h4>
Use a tool like Postman or Swagger to test the API endpoints.<br/>
<h4>**For authentication, use the JWT token provided upon login for authorized endpoints.**</h4>
<h3>Future Enhancements</h3>
<h4>a. Add Two-Factor Authentication (2FA) for enhanced security.</h4>
<h4>b.Implement social login options (e.g., Google, Facebook).</h4>
<h4>c. Add user roles and permission-based authorization.</h4>
<h4>d.Include advanced logging and monitoring.</h4>
<h3>Contributing</h3>
Contributions are welcome! Feel free to open issues or submit pull requests to enhance the project.

<h3>License</h3>
This project is licensed under the MIT License.

<h3>Contact</h3>
For inquiries or support, feel free to contact me:

Email: iphieaijay@outlook.com
