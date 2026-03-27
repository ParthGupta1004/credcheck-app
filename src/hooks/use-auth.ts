"use client"

import { useSession, signIn, signOut } from "next-auth/react"
import type { UserRole } from "@/lib/auth"

interface UseAuthReturn {
  // Session data
  user: {
    id: string
    email: string
    name?: string | null
    image?: string | null
    role: UserRole
    college?: string | null
    degree?: string | null
    batch?: string | null
    verified: boolean
  } | null
  isAuthenticated: boolean
  isLoading: boolean

  // Role checks
  isStudent: boolean
  isVerifier: boolean
  isAdmin: boolean

  // Actions
  login: () => Promise<void>
  logout: () => Promise<void>
}

/**
 * Custom hook for authentication and session management
 * Provides easy access to session data and role-based checks
 */
export function useAuth(): UseAuthReturn {
  const { data: session, status } = useSession()

  const user = session?.user ?? null
  const isAuthenticated = status === "authenticated"
  const isLoading = status === "loading"

  // Role checks
  const isStudent = user?.role === "student"
  const isVerifier = user?.role === "verifier"
  const isAdmin = user?.role === "admin"

  // Actions
  const login = async () => {
    await signIn("google", { callbackUrl: "/" })
  }

  const logout = async () => {
    await signOut({ callbackUrl: "/" })
  }

  return {
    user,
    isAuthenticated,
    isLoading,
    isStudent,
    isVerifier,
    isAdmin,
    login,
    logout,
  }
}

/**
 * Type guard to check if user has a specific role
 */
export function hasRole(userRole: UserRole | undefined, role: UserRole): boolean {
  return userRole === role
}

/**
 * Type guard to check if user has any of the specified roles
 */
export function hasAnyRole(userRole: UserRole | undefined, roles: UserRole[]): boolean {
  return userRole !== undefined && roles.includes(userRole)
}

/**
 * Check if user can verify certificates
 * Both verifiers and admins can verify certificates
 */
export function canVerify(userRole: UserRole | undefined): boolean {
  return userRole === "verifier" || userRole === "admin"
}

/**
 * Check if user can manage users (admin only)
 */
export function canManageUsers(userRole: UserRole | undefined): boolean {
  return userRole === "admin"
}
