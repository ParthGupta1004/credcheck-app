# CredCheck: Secure Certificate Verification Platform

CredCheck is a robust, full-stack application designed to issue, verify, and manage academic or professional certificates. It provides a secure, non-repudiable verification loop between students, issuing organizations, and administrators.

## 🚀 Key Features

### 🎓 For Students
- **Digital Portfolio**: Upload and manage all your academic and professional certificates in one secure place.
- **Real-time Tracking**: Monitor the status of your verification requests (Pending, Approved, or Rejected).
- **One-Click Sharing**: Generate public links and QR codes to share your verified credentials with employers or on social media.
- **Abuse Reporting**: Flag any unauthorized or incorrect certificates associated with your profile.

### 🛡️ For Verifiers (Organizations)
- **Organization Dashboard**: Manage verification requests from students assigned to your organization.
- **Non-Repudiable Approval**: Digitally approve certificates, which automatically signs them with a unique public link and QR code.
- **Custom Feedback**: Provide specific reasons or comments when rejecting a certificate request.
- **Verification History**: Maintain a complete log of all certificates issued and verified by your organization.

### ⚙️ For Administrators
- **System Oversight**: Monitor platform-wide statistics, including total users, verifiers, and verified certificates.
- **User Management**: Approve or reject new organization/verifier requests and manage user roles.
- **Security Control**: Review and resolve **Abuse Reports** filed by the community to maintain platform integrity.
- **Database Maintenance**: Tools to manage and audit the underlying certificate records.

### 💻 System-Wide Innovations
- **In-App Notification System**: Real-time alerts delivered via the dashboard "Bell" icon for instant feedback on all certificate actions.
- **Dynamic QR Code Connectivity**: A smart utility that detects your local network IP (IPv4) during development, allowing physical mobile devices to scan and verify QR codes on local Wi-Fi.
- **Automated Email Engine**: SMTP-integrated notifications (Gmail optimized) sent to students and verifiers for every major status change.
- **Responsive & Premium UI**: Built with a "dark-mode first" aesthetic using Tailwind CSS and Shadcn UI for a professional, high-end feel.

## 🚀 Tech Stack

- **Framework**: Next.js 16 (App Router)
- **Database**: SQLite (managed via Prisma ORM)
- **Styling**: Tailwind CSS + Shadcn UI
- **Authentication**: NextAuth.js
- **Email**: SMTP / Nodemailer (Gmail support included)
- **Animations**: Framer Motion
- **Icons**: Lucide React

---

## 🛠️ Installation & Setup

Follow these steps to get the project running on your local machine:

### 1. Clone & Install
```bash
# Clone the repository
cd credcheck-platform

# Install dependencies
npm install
```

### 2. Environment Configuration
Create a `.env` file in the root directory and copy the following (update with your credentials):

```env
# Database
DATABASE_URL="file:./dev.db"

# Authentication
NEXTAUTH_SECRET="your-secret-key"
NEXTAUTH_URL="http://localhost:3000"

# App URL (Must match production domain once deployed)
NEXT_PUBLIC_APP_URL="http://localhost:3000"

# Email Configuration (SMTP)
EMAIL_USER="your-email@gmail.com"
EMAIL_PASS="your-app-specific-password"
EMAIL_FROM="CredCheck <your-email@gmail.com>"
```

### 3. Database Migration
```bash
# Push the schema to your local SQLite database
npx prisma db push

# Generate the Prisma client
npx prisma generate
```

### 4. Run Development Server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 👥 User Roles & Workflows

### 🎓 Student
1. **Register/Login** to the Student Dashboard.
2. **Upload** a certificate image/PDF and assign a Verifier's email.
3. **Wait** for the Verifier to review. You will receive an **In-App Notification** and an **Email** once approved.
4. **Share** your verified public link or QR code with employers.

### 🛡️ Verifier
1. **Login** to the Verifier Dashboard.
2. **Review** pending requests from students.
3. **Approve/Reject** certificates. Approved certificates automatically generate a unique QR code and public link.
4. **Notifications**: Stay updated on new submissions via the header bell icon.

### ⚙️ Administrator
1. **Global Overview**: Monitor user registrations and system stats.
2. **Manage Users**: Review verifier organization requests and user roles.
3. **Security**: Investigate and resolve **Abuse Reports** filed by users.

---

## 📱 Mobile Verification (Dev Mode)
Unlike standard local apps, CredCheck automatically detects your local Wi-Fi IP address when generating QR codes. This allows you to **scan the QR code on your physical phone** and view the certificate instantly as long as you are on the same Wi-Fi network.

## 🚢 Deployment
The project is ready for deployment on **Vercel**, Netlify, or any Node.js environment.
1. Set the `NEXT_PUBLIC_APP_URL` and `NEXTAUTH_URL` to your production domain.
2. Ensure your SMTP credentials are securely added to your environment variables.
3. Run `npm run build` and `npm start`.

---
