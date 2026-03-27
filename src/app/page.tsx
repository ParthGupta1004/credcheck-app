"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import { useSession } from "next-auth/react";
import {
  Shield,
  GraduationCap,
  Building2,
  ArrowRight,
  CheckCircle2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Header } from "@/components/layout/header";
import { Footer } from "@/components/layout/footer";

const dashboardOptions = [
  {
    icon: GraduationCap,
    title: "Student Dashboard",
    description:
      "Upload certificates, request verification, and share verified credentials with recruiters.",
    features: [
      "Upload certificates (PDF/Image)",
      "Request verification",
      "Share via QR code or link",
      "Track verification status",
    ],
    href: "/dashboard/student",
    registerHref: "/register?role=student",
    color: "text-emerald-500",
    bgColor: "bg-emerald-500/10",
    borderColor: "border-emerald-500/30",
    role: "student",
  },
  {
    icon: Building2,
    title: "Verifier Dashboard",
    description:
      "Review and verify student certificates. Manage verification requests from institutions.",
    features: [
      "Review certificate requests",
      "Approve or reject certificates",
      "Manage verification queue",
      "Build institution credibility",
    ],
    href: "/dashboard/verifier",
    registerHref: "/register?role=verifier",
    color: "text-amber-500",
    bgColor: "bg-amber-500/10",
    borderColor: "border-amber-500/30",
    role: "verifier",
  },
  {
    icon: Shield,
    title: "Admin Dashboard",
    description:
      "Manage the entire platform. Oversee users, verifiers, and maintain system integrity.",
    features: [
      "Manage all users",
      "Approve verifier requests",
      "Handle abuse reports",
      "Platform analytics",
    ],
    href: "/dashboard/admin",
    registerHref: "/register?role=admin",
    color: "text-violet-500",
    bgColor: "bg-violet-500/10",
    borderColor: "border-violet-500/30",
    role: "admin",
  },
];

export default function HomePage() {
  const { data: session, status } = useSession();

  return (
    <div className="flex min-h-screen flex-col">
      <Header />

      <main className="flex-1">
        {/* Hero Section */}
        <section className="relative overflow-hidden bg-gradient-to-b from-emerald-50 via-background to-background dark:from-emerald-950/20">
          <div className="absolute inset-0 bg-grid-slate-100 [mask-image:linear-gradient(0deg,transparent,black)] dark:bg-grid-slate-900" />

          <div className="relative mx-auto max-w-7xl px-4 py-12 sm:px-6 sm:py-16 lg:px-8">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
              className="text-center"
            >
              <Badge variant="secondary" className="mb-4 px-4 py-1.5 text-sm">
                <Shield className="mr-2 h-4 w-4" />
                CredCheck Platform
              </Badge>

              <h1 className="text-4xl font-bold tracking-tight text-foreground sm:text-5xl">
                Certificate Verification
                <span className="block text-primary mt-2">Made Simple</span>
              </h1>

              <p className="mx-auto mt-4 max-w-2xl text-lg text-muted-foreground">
                {status === "authenticated" && session?.user
                  ? `Welcome back, ${session.user.name || session.user.email}! Select your dashboard to continue.`
                  : "Choose your dashboard to get started. Register or sign in to access your dashboard."}
              </p>
            </motion.div>
          </div>
        </section>

        {/* Dashboard Selection */}
        <section className="py-12 sm:py-16">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="grid gap-6 lg:grid-cols-3">
              {dashboardOptions.map((option, index) => {
                const isCurrentUser = status === "authenticated" && session?.user?.role === option.role;
                
                return (
                  <motion.div
                    key={option.title}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1, duration: 0.4 }}
                  >
                    <Card className={`relative h-full overflow-hidden transition-all hover:shadow-lg hover:-translate-y-1 border-2 ${isCurrentUser ? option.borderColor : "border-border"}`}>
                      {isCurrentUser && (
                        <div className={`absolute top-0 left-0 right-0 h-1 ${option.color.replace("text-", "bg-")}`} />
                      )}
                      <CardHeader className="pb-3">
                        <div className="flex items-center justify-between">
                          <div className={`flex h-12 w-12 items-center justify-center rounded-xl ${option.bgColor}`}>
                            <option.icon className={`h-6 w-6 ${option.color}`} />
                          </div>
                          {isCurrentUser && (
                            <Badge variant="outline" className={`${option.color} border-current`}>
                              Current
                            </Badge>
                          )}
                        </div>
                        <CardTitle className="text-lg mt-3">{option.title}</CardTitle>
                        <CardDescription className="text-sm">
                          {option.description}
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        <ul className="space-y-1.5">
                          {option.features.map((feature) => (
                            <li
                              key={feature}
                              className="flex items-center gap-2 text-sm text-muted-foreground"
                            >
                              <CheckCircle2 className={`h-3.5 w-3.5 ${option.color}`} />
                              {feature}
                            </li>
                          ))}
                        </ul>
                        
                        {status === "authenticated" ? (
                          // User is logged in - show dashboard button
                          <Button 
                            asChild 
                            className={`w-full gap-2 ${isCurrentUser ? "" : "variant-outline"}`}
                            variant={isCurrentUser ? "default" : "outline"}
                          >
                            <Link href={option.href}>
                              Open Dashboard
                              <ArrowRight className="h-4 w-4" />
                            </Link>
                          </Button>
                        ) : (
                          // User not logged in - show register button
                          <Button asChild className="w-full gap-2">
                            <Link href={option.registerHref}>
                              Get Started
                              <ArrowRight className="h-4 w-4" />
                            </Link>
                          </Button>
                        )}
                      </CardContent>
                    </Card>
                  </motion.div>
                );
              })}
            </div>
          </div>
        </section>

        {/* Info Section */}
        <section className="border-t border-border bg-muted/30 py-8">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="text-center">
              <p className="text-muted-foreground">
                {status === "authenticated" 
                  ? "Click on any dashboard to access your panel."
                  : "New users are registered as students by default. You can change your role during registration."}
              </p>
            </div>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  );
}
