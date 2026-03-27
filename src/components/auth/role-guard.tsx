"use client";

import { useEffect } from "react";
import { useSession } from "next-auth/react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";

type UserRole = "student" | "verifier" | "admin";

interface RoleGuardProps {
  allowedRole: UserRole;
  children: React.ReactNode;
}

export function RoleGuard({ allowedRole, children }: RoleGuardProps) {
  const { data: session, status } = useSession();
  const router = useRouter();

  useEffect(() => {
    if (status === "unauthenticated") {
      // Not logged in, redirect to login
      router.push("/login");
    } else if (status === "authenticated" && session?.user) {
      const userRole = session.user.role as UserRole;
      if (userRole !== allowedRole) {
        // Logged in but wrong role, redirect to home
        router.push("/");
      }
    }
  }, [status, session, allowedRole, router]);

  // Show loading while checking auth
  if (status === "loading") {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto mb-4" />
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  // Not authenticated or wrong role - show loading while redirecting
  if (status === "unauthenticated" || (session?.user && session.user.role !== allowedRole)) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto mb-4" />
          <p className="text-muted-foreground">Redirecting...</p>
        </div>
      </div>
    );
  }

  // Authenticated with correct role
  return <>{children}</>;
}
