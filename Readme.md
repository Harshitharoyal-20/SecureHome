# SecureHome – Smart Security System

## 1. Project Description

SecureHome is a context-aware private room protection and smart locker security system designed to protect valuable items such as jewellery, documents, and electronic devices.

The system provides secure user authentication, role-based access control, locker management, access history tracking, and security alert management. Administrators can manage secure assets and grant permissions to authorized users. Family members and other authorized users can view only the assets they are permitted to access.

The application uses a React frontend, a Spring Boot backend, and a MySQL database to manage users, secure assets, permissions, and security events.

### Key Features
- GitHub OAuth authentication.
- Role-based access control for administrators and regular users.
- Secure locker and asset management.
- Permission-based access to lockers.
- Access history tracking.
- Security alerts restricted to authorized administrators.
- Web-based dashboard for monitoring secure assets.

## 2. Technology Stack

| Component | Technology |
|---|---|
| Frontend | React.js, JavaScript, CSS |
| Frontend build tool | Vite |
| Backend | Java 21, Spring Boot |
| Security | Spring Security, GitHub OAuth 2.0 |
| Database | MySQL 8 |
| Database integration | Spring Data JPA, Hibernate, JDBC |
| Build tool | Maven |
| Version control | Git and GitHub |
| Frontend deployment | Vercel |
| Backend deployment | Render |
| Database hosting | Aiven MySQL |

## 3. Installation Steps

### Prerequisites

Install the following software:

- Java Development Kit (JDK) 21.
- Node.js and npm.
- Git.
- MySQL database or an accessible Aiven MySQL instance.
- Visual Studio Code or another code editor.

### Step 1: Clone the Repository

Open a terminal and execute:

```bash
git clone https://github.com/Harshitharoyal-20/SecureHome.git
cd SecureHome
```

### Step 2: Configure the Database

Create or configure the MySQL database named `home_security`.

Configure the following environment variables for the backend using your database connection details:

```text
DB_URL=jdbc:mysql://HOST:PORT/home_security
DB_USERNAME=YOUR_DATABASE_USERNAME
DB_PASSWORD=YOUR_DATABASE_PASSWORD
```

Replace the example values with your actual database details. For a hosted database, use the connection information provided by your database provider.

### Step 3: Configure GitHub OAuth

Create or configure a GitHub OAuth application with the callback URL matching the backend's configured OAuth login callback.

Set the following environment variables:

```text
GITHUB_CLIENT_ID=YOUR_GITHUB_CLIENT_ID
GITHUB_CLIENT_SECRET=YOUR_GITHUB_CLIENT_SECRET
```

Keep credentials private. Do not commit database passwords or OAuth client secrets to GitHub.

### Step 4: Install Backend Dependencies

Open a terminal in the backend directory:

```bash
cd home-security
```

On Windows, build the backend using:

```powershell
.\mvnw.cmd clean package -DskipTests
```

On Linux or macOS, use:

```bash
./mvnw clean package -DskipTests
```

The command builds the application without running the tests. Ensure the database and environment variables are configured before running database-dependent tests.

### Step 5: Install Frontend Dependencies

Open another terminal in the repository root and run:

```bash
cd home-security-frontend
npm install
```

## 4. Execution Steps

### Step 1: Start the Backend

Navigate to the backend directory and run the Spring Boot application.

On Windows:

```powershell
.\mvnw.cmd spring-boot:run
```

On Linux or macOS:

```bash
./mvnw spring-boot:run
```

The backend runs on port `8080` by default, unless another port is configured.

Backend URL:

```text
http://localhost:8080
```

### Step 2: Start the Frontend

Open a separate terminal in the frontend directory:

```bash
cd home-security-frontend
npm run dev
```

Vite displays the local frontend URL in the terminal. Open that URL in your browser; it is usually:

```text
http://localhost:5173
```

Configure the frontend's API base URL, if required by the project, to point to the running backend.

### Step 3: Use the Application

1. Open the frontend in your browser.
2. Sign in using the configured GitHub authentication.
3. View the security dashboard.
4. Open **My Lockers** to view accessible secure assets.
5. Open **Access History** to review available access records.
6. Administrators can manage assets, grant permissions, and access security alerts according to their assigned privileges.

## 5. Deployment

The project can be deployed using the following services:

- **Frontend:** Vercel.
- **Backend:** Render.
- **Database:** Aiven MySQL.

Configure the required environment variables in the deployment settings. Ensure the frontend points to the deployed backend, the backend can connect to the database, and the GitHub OAuth callback matches the deployed backend URL.

## 6. Repository Structure

```text
SecureHome/
├── home-security/
│   ├── src/
│   ├── pom.xml
│   └── mvnw
└── home-security-frontend/
    ├── src/
    ├── public/
    ├── package.json
    └── vite.config.js
```

The backend directory contains the Spring Boot application, while the frontend directory contains the React application.

## 7. Conclusion

SecureHome provides a web-based approach to private room and smart locker security. By combining authentication, role-based authorization, permission management, access history, and administrator-controlled security alerts, the system helps manage access to valuable assets through a centralized application.

## 8. Contributors & Development Team

| Contributor | GitHub Account | Email | Role & Contribution |
|---|---|---|---|
| **Harshitha** | [@Harshitharoyal-20](https://github.com/Harshitharoyal-20) | `harshithasree54@gmail.com` | Primary Administrator, Backend & Frontend Core Architecture, Deployment |
| **G. S. Pranawii** | [@GSPranawii](https://github.com/GSPranawii) | `pranawiiguda@gmail.com` | Family Member Administrator, Temporary Permission Delegation & Access Portal Management |
| **Sivakumar** | - | `sivakumar6413@gmail.com` | System Administrator, Security Rules & Policies |
| **Mahesh** | - | `mahesh0562@gmail.com` | Security Personnel, High-Risk Security Alerts & Locker Auditing |

## 9. Family Admin & Permission Delegation Portal

The access management system allows family member administrators (`harshitha0064@gmail.com`, `pranawii0713@gmail.com`, `sivakumar6413@gmail.com`) to:
- Dynamically grant and revoke time-bound access permissions to secure lockers for authenticated users.
- Audit real-time access events and view historical access records with paginated entries.
- Receive immediate notification badges when unauthorized or new accounts attempt access.

**GitHub Repository:** https://github.com/Harshitharoyal-20/SecureHome

**Live Application:** https://secure-home-kappa.vercel.app/
