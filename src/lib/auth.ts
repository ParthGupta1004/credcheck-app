import type { NextAuthOptions } from "next-auth"
import CredentialsProvider from "next-auth/providers/credentials"
import { PrismaAdapter } from "@auth/prisma-adapter"
import bcrypt from "bcryptjs"
import { db } from "./db"

// User role type
export type UserRole = "student" | "verifier" | "admin"

// Extend NextAuth types
declare module "next-auth" {
  interface Session {
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
    }
  }

  interface User {
    id: string
    role: UserRole
    college?: string | null
    degree?: string | null
    batch?: string | null
    verified: boolean
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    id: string
    role: UserRole
    college?: string | null
    degree?: string | null
    batch?: string | null
    verified: boolean
  }
}

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(db) as NextAuthOptions["adapter"],
  providers: [
    CredentialsProvider({
      id: "credentials",
      name: "Email and Password",
      credentials: {
        email: { label: "Email", type: "email", placeholder: "Enter your email" },
        password: { label: "Password", type: "password", placeholder: "Enter your password" },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          throw new Error("Email and password are required")
        }

        const email = credentials.email.toLowerCase()

        // Find user in database
        const user = await db.user.findUnique({
          where: { email },
        })

        if (!user) {
          throw new Error("No user found with this email")
        }

        // Check if user has a password (might be OAuth user)
        if (!user.password) {
          throw new Error("Please sign in with your original method")
        }

        // Verify password
        const isValidPassword = await bcrypt.compare(credentials.password, user.password)

        if (!isValidPassword) {
          throw new Error("Invalid password")
        }

        return {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role as UserRole,
          college: user.college,
          degree: user.degree,
          batch: user.batch,
          verified: user.verified,
        }
      },
    }),
  ],
  pages: {
    signIn: "/login",
    error: "/login",
  },
  session: {
    strategy: "jwt",
  },
  callbacks: {
    async signIn({ user, account }) {
      // Allow sign in for all providers
      return true
    },
    async jwt({ token, user, trigger, session }) {
      // Initial sign in - add user data to token
      if (user) {
        token.id = user.id
        token.role = user.role
        token.college = user.college
        token.degree = user.degree
        token.batch = user.batch
        token.verified = user.verified
      }

      // Update token when session is updated
      if (trigger === "update" && session) {
        token.role = session.user.role
        token.college = session.user.college
        token.degree = session.user.degree
        token.batch = session.user.batch
        token.verified = session.user.verified
      }

      return token
    },
    async session({ session, token }) {
      if (token) {
        session.user.id = token.id
        session.user.role = token.role
        session.user.college = token.college
        session.user.degree = token.degree
        session.user.batch = token.batch
        session.user.verified = token.verified
      }
      return session
    },
  },
  events: {
    async signIn({ user, isNewUser }) {
      console.log(`User ${user.email} signed in. New user: ${isNewUser}`)
    },
  },
  debug: process.env.NODE_ENV === "development",
}

// Helper function to get the current session on the server side
export async function getServerSession() {
  const { getServerSession } = await import("next-auth")
  return getServerSession(authOptions)
}
