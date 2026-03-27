import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";
import { ThemeProvider } from "@/components/providers/theme-provider";
import { SessionProvider } from "@/components/providers/session-provider";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "CredCheck - Secure Certificate Verification Platform",
  description: "Verify certificates instantly with CredCheck. Secure, reliable certificate verification for students, institutions, and recruiters. Build trust with every document.",
  keywords: ["Certificate Verification", "Document Verification", "Credentials", "CredCheck", "Secure Verification", "QR Code Verification"],
  authors: [{ name: "CredCheck Team" }],
  icons: {
    icon: "/favicon.ico",
  },
  openGraph: {
    title: "CredCheck - Secure Certificate Verification",
    description: "Verify certificates instantly. Secure, reliable verification for students, institutions, and recruiters.",
    url: "https://credcheck.com",
    siteName: "CredCheck",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "CredCheck - Secure Certificate Verification",
    description: "Verify certificates instantly. Secure, reliable verification for students, institutions, and recruiters.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
        suppressHydrationWarning
      >
        <SessionProvider>
          <ThemeProvider
            attribute="class"
            defaultTheme="system"
            enableSystem
            disableTransitionOnChange
          >
            {children}
            <Toaster />
          </ThemeProvider>
        </SessionProvider>
      </body>
    </html>
  );
}
