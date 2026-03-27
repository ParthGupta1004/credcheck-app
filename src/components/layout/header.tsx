"use client";

import { useState } from "react";
import Link from "next/link";
import { useSession, signOut } from "next-auth/react";
import { motion, AnimatePresence } from "framer-motion";
import { Menu, X, Shield, LogOut, LayoutDashboard, GraduationCap, Building2, User, Lock } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

type UserRole = "student" | "verifier" | "admin";

const roleConfig = {
  student: {
    icon: GraduationCap,
    color: "text-emerald-500",
    bgColor: "bg-emerald-500/10",
    label: "Student",
  },
  verifier: {
    icon: Building2,
    color: "text-amber-500",
    bgColor: "bg-amber-500/10",
    label: "Verifier",
  },
  admin: {
    icon: Shield,
    color: "text-violet-500",
    bgColor: "bg-violet-500/10",
    label: "Admin",
  },
};

export function Header() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const { data: session, status } = useSession();

  const userRole = session?.user?.role as UserRole | undefined;
  const currentRoleConfig = userRole ? roleConfig[userRole] : null;

  const handleSignOut = async () => {
    await signOut({ redirect: false });
    window.location.href = "/";
  };

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border/40 bg-background/80 backdrop-blur-lg">
      <nav className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3 sm:px-6 lg:px-8">
        {/* Logo */}
        <Link href="/" className="flex items-center gap-2">
          <motion.div
            whileHover={{ rotate: 360 }}
            transition={{ duration: 0.5 }}
            className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary"
          >
            <Shield className="h-4 w-4 text-primary-foreground" />
          </motion.div>
          <span className="text-lg font-bold text-foreground">
            Cred<span className="text-primary">Check</span>
          </span>
        </Link>

        {/* Desktop Navigation */}
        <div className="hidden md:flex md:items-center md:gap-1">
          <Link
            href="/"
            className="rounded-lg px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
          >
            Home
          </Link>
          
          {status === "authenticated" && userRole ? (
            // Show only the user's dashboard link
            <Link
              href={`/dashboard/${userRole}`}
              className={cn(
                "flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-colors hover:bg-accent",
                currentRoleConfig?.color
              )}
            >
              {currentRoleConfig && (
                <currentRoleConfig.icon className="h-4 w-4" />
              )}
              {currentRoleConfig?.label} Dashboard
            </Link>
          ) : (
            // Not logged in - show all dashboards but indicate login required
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="gap-1 text-sm">
                  Dashboards
                  <Lock className="h-3 w-3 ml-1" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-48">
                <DropdownMenuItem disabled className="opacity-60">
                  <GraduationCap className="h-4 w-4 mr-2 text-emerald-500" />
                  Student Dashboard
                </DropdownMenuItem>
                <DropdownMenuItem disabled className="opacity-60">
                  <Building2 className="h-4 w-4 mr-2 text-amber-500" />
                  Verifier Dashboard
                </DropdownMenuItem>
                <DropdownMenuItem disabled className="opacity-60">
                  <Shield className="h-4 w-4 mr-2 text-violet-500" />
                  Admin Dashboard
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem asChild>
                  <Link href="/login" className="w-full">
                    Sign in to access
                  </Link>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>

        {/* Auth Buttons - Desktop */}
        <div className="hidden md:flex md:items-center md:gap-2">
          {status === "authenticated" && session?.user ? (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="gap-2">
                  <div className={cn("flex h-7 w-7 items-center justify-center rounded-full", currentRoleConfig?.bgColor || "bg-muted")}>
                    {currentRoleConfig ? (
                      <currentRoleConfig.icon className={cn("h-3.5 w-3.5", currentRoleConfig.color)} />
                    ) : (
                      <User className="h-3.5 w-3.5" />
                    )}
                  </div>
                  <span className="hidden sm:inline max-w-[120px] truncate">{session.user.name || session.user.email}</span>
                  {currentRoleConfig && (
                    <Badge variant="outline" className={cn("text-xs", currentRoleConfig.color, currentRoleConfig.bgColor)}>
                      {currentRoleConfig.label}
                    </Badge>
                  )}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-48">
                <DropdownMenuItem asChild>
                  <Link href={`/dashboard/${userRole || "student"}`} className="flex items-center gap-2">
                    <LayoutDashboard className="h-4 w-4" />
                    My Dashboard
                  </Link>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={handleSignOut} className="flex items-center gap-2 text-destructive focus:text-destructive">
                  <LogOut className="h-4 w-4" />
                  Sign Out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          ) : (
            <>
              <Button variant="ghost" asChild size="sm">
                <Link href="/login">Sign In</Link>
              </Button>
              <Button asChild size="sm">
                <Link href="/register">Get Started</Link>
              </Button>
            </>
          )}
        </div>

        {/* Mobile Menu Button */}
        <Button
          variant="ghost"
          size="icon"
          className="md:hidden"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
        >
          {mobileMenuOpen ? (
            <X className="h-5 w-5" />
          ) : (
            <Menu className="h-5 w-5" />
          )}
        </Button>
      </nav>

      {/* Mobile Menu */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.2 }}
            className="border-t border-border/40 bg-background md:hidden"
          >
            <div className="space-y-1 px-4 py-4">
              <Link
                href="/"
                onClick={() => setMobileMenuOpen(false)}
                className="block rounded-lg px-4 py-3 text-base font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
              >
                Home
              </Link>
              
              {status === "authenticated" && userRole ? (
                <Link
                  href={`/dashboard/${userRole}`}
                  onClick={() => setMobileMenuOpen(false)}
                  className={cn(
                    "flex items-center gap-2 rounded-lg px-4 py-3 text-base font-medium transition-colors hover:bg-accent",
                    currentRoleConfig?.color
                  )}
                >
                  {currentRoleConfig && (
                    <currentRoleConfig.icon className="h-5 w-5" />
                  )}
                  {currentRoleConfig?.label} Dashboard
                </Link>
              ) : (
                <div className="px-4 py-3 text-muted-foreground flex items-center gap-2">
                  <Lock className="h-4 w-4" />
                  <span className="text-sm">Sign in to access dashboard</span>
                </div>
              )}
              
              <div className="mt-4 flex flex-col gap-2 border-t border-border/40 pt-4">
                {status === "authenticated" && session?.user ? (
                  <>
                    <Button variant="outline" asChild className="w-full justify-start">
                      <Link href={`/dashboard/${userRole || "student"}`} onClick={() => setMobileMenuOpen(false)}>
                        <LayoutDashboard className="mr-2 h-4 w-4" />
                        My Dashboard
                      </Link>
                    </Button>
                    <Button variant="destructive" className="w-full justify-start" onClick={handleSignOut}>
                      <LogOut className="mr-2 h-4 w-4" />
                      Sign Out
                    </Button>
                  </>
                ) : (
                  <>
                    <Button variant="outline" asChild className="w-full justify-start">
                      <Link href="/login" onClick={() => setMobileMenuOpen(false)}>
                        Sign In
                      </Link>
                    </Button>
                    <Button asChild className="w-full">
                      <Link href="/register" onClick={() => setMobileMenuOpen(false)}>
                        Get Started
                      </Link>
                    </Button>
                  </>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
}
