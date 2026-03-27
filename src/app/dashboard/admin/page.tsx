"use client";

import { useState, useEffect } from "react";
import { useSession, signOut } from "next-auth/react";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Users,
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
  LogOut,
  Home,
  Menu,
  Shield,
  Settings,
  Bell,
  Camera,
  Loader2,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { StatsOverview } from "@/components/admin/stats-overview";
import { UsersTable } from "@/components/admin/users-table";
import { VerifiersTable } from "@/components/admin/verifiers-table";
import { AbuseReports } from "@/components/admin/abuse-reports";
import { RoleGuard } from "@/components/auth/role-guard";
import { NotificationList } from '@/components/notifications/notification-list';
import { NotificationBell } from '@/components/notifications/notification-bell';
import Link from "next/link";

interface Stats {
  totalUsers: number;
  totalCertificates: number;
  totalVerifiers: number;
  pendingRequests: number;
}

interface User {
  id: string;
  email: string;
  name: string | null;
  image: string | null;
  role: string;
  college: string | null;
  degree: string | null;
  batch: string | null;
  verified: boolean;
  createdAt: string;
  _count?: {
    certificates: number;
  };
}

interface VerifierRequest {
  id: string;
  organizationName: string;
  organizationEmail: string;
  description: string | null;
  website: string | null;
  logoUrl: string | null;
  status: string;
  requestedAt: string;
  reviewedAt: string | null;
  user: {
    id: string;
    name: string | null;
    email: string;
    image: string | null;
  };
}

interface AbuseReport {
  id: string;
  reason: string;
  status: string;
  createdAt: string;
  reviewedAt: string | null;
  reporter: {
    id: string;
    name: string | null;
    email: string;
    image: string | null;
  };
  certificate: {
    id: string;
    title: string;
    organization: string;
    publicLinkId: string;
    student: {
      name: string | null;
      email: string;
    };
  };
}

export default function AdminDashboard() {
  const { data: session, update: updateSession } = useSession();
  const router = useRouter();
  const { toast } = useToast();
  
  const [stats, setStats] = useState<Stats | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [verifierRequests, setVerifierRequests] = useState<VerifierRequest[]>([]);
  const [abuseReports, setAbuseReports] = useState<AbuseReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [activeTab, setActiveTab] = useState<"users" | "verifiers" | "reports" | "settings" | "notifications">("users");
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [uploadingImage, setUploadingImage] = useState(false);

  const handleImageUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith('image/')) {
      toast({ title: "Error", description: "Please select an image file", variant: "destructive" });
      return;
    }

    if (file.size > 5 * 1024 * 1024) {
      toast({ title: "Error", description: "Image must be less than 5MB", variant: "destructive" });
      return;
    }

    setUploadingImage(true);
    try {
      const formData = new FormData();
      formData.append('file', file);

      const uploadRes = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      if (!uploadRes.ok) throw new Error('Upload failed');
      const { fileUrl } = await uploadRes.json();

      const profileRes = await fetch('/api/user/profile', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ image: fileUrl }),
      });

      if (!profileRes.ok) throw new Error('Profile update failed');

      await updateSession({ image: fileUrl });
      toast({ title: "Success", description: "Profile image updated!" });
    } catch (error) {
      toast({ title: "Error", description: "Failed to upload image", variant: "destructive" });
    } finally {
      setUploadingImage(false);
    }
  };

  const fetchData = async () => {
    try {
      const [statsRes, usersRes, verifiersRes, reportsRes] = await Promise.all([
        fetch("/api/admin/stats"),
        fetch("/api/admin/users"),
        fetch("/api/admin/verifier-requests"),
        fetch("/api/admin/abuse-reports"),
      ]);

      if (statsRes.ok) {
        setStats(await statsRes.json());
      }
      if (usersRes.ok) {
        setUsers(await usersRes.json());
      }
      if (verifiersRes.ok) {
        setVerifierRequests(await verifiersRes.json());
      }
      if (reportsRes.ok) {
        setAbuseReports(await reportsRes.json());
      }
    } catch (error) {
      console.error("Failed to fetch data:", error);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
  };

  const handleSignOut = async () => {
    await signOut({ redirect: false });
    router.push('/');
  };

  const pendingVerifiers = verifierRequests.filter((r) => r.status === "pending").length;
  const pendingReports = abuseReports.filter((r) => r.status === "pending").length;

  if (loading) {
    return (
      <RoleGuard allowedRole="admin">
        <div className="min-h-screen bg-background">
          {/* Skeleton Header combining sleek layout */}
          <header className="sticky top-0 z-40 border-b bg-background/95 backdrop-blur px-4 md:px-6 h-16 flex items-center">
            <Skeleton className="h-8 w-8 rounded-lg mr-2" />
            <Skeleton className="h-6 w-32" />
          </header>
          <div className="flex">
             <aside className="hidden md:block w-64 border-r min-h-[calc(100vh-4rem)] p-4">
                <Skeleton className="h-10 w-full mb-2" />
                <Skeleton className="h-10 w-full mb-2" />
                <Skeleton className="h-10 w-full" />
             </aside>
             <main className="flex-1 p-4 md:p-6 space-y-6">
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4 mb-6">
                  {[1, 2, 3, 4].map((i) => (
                    <Card key={i}>
                      <CardHeader className="pb-2">
                        <Skeleton className="h-4 w-24" />
                      </CardHeader>
                      <CardContent>
                        <Skeleton className="h-8 w-16 mb-1" />
                        <Skeleton className="h-3 w-32" />
                      </CardContent>
                    </Card>
                  ))}
                </div>
                <Skeleton className="h-[400px] w-full" />
             </main>
          </div>
        </div>
      </RoleGuard>
    );
  }

  return (
    <RoleGuard allowedRole="admin">
      <div className="min-h-screen bg-background text-foreground">
        {/* Header */}
        <header className="sticky top-0 z-40 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
          <div className="flex h-16 items-center px-4 md:px-6">
            <Button
              variant="ghost"
              size="icon"
              className="md:hidden mr-2"
              onClick={() => setIsSidebarOpen(!isSidebarOpen)}
            >
              <Menu className="h-5 w-5" />
            </Button>
            
            <Link href="/" className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-violet-600 text-white shadow-md">
                <Shield className="h-4 w-4" />
              </div>
              <span className="font-bold text-lg hidden sm:inline-block">CredCheck</span>
            </Link>
            <Badge className="bg-violet-600 hover:bg-violet-700 ml-3">Admin</Badge>

            <div className="ml-auto flex items-center gap-2">
              <div className="hidden sm:flex items-center gap-3 mr-4">
                <div className="flex h-9 w-9 items-center justify-center rounded-full bg-violet-500/10 text-violet-600 font-bold border-2 border-violet-500/20 overflow-hidden">
                  {session?.user?.image ? (
                    <img src={session.user.image} alt="Profile" className="h-full w-full object-cover" />
                  ) : (
                    (session?.user?.name || session?.user?.email || 'A').charAt(0).toUpperCase()
                  )}
                </div>
              </div>
              <Button
                variant="ghost"
                size="icon"
                onClick={handleRefresh}
                title="Refresh Data"
                disabled={refreshing}
                className="hidden sm:inline-flex"
              >
                <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin text-violet-600" : ""}`} />
              </Button>
              <Link href="/">
                <Button variant="ghost" size="icon" title="Home">
                  <Home className="h-4 w-4" />
                </Button>
              </Link>
              <Button variant="ghost" size="icon" title="Notifications" onClick={() => { setActiveTab('notifications'); setIsSidebarOpen(false); }}>
                <NotificationBell className="h-4 w-4" />
              </Button>
              <Button variant="ghost" size="icon" onClick={handleSignOut} title="Logout">
                <LogOut className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </header>

        <div className="flex">
          {/* Sidebar */}
          <aside
            className={`
              fixed inset-y-0 left-0 z-30 w-64 transform border-r bg-background
              transition-transform duration-200 ease-in-out md:translate-x-0 md:static top-16 md:top-0
              ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'}
              h-[calc(100vh-4rem)] overflow-y-auto
            `}
          >
            <nav className="flex flex-col gap-1 p-4">
              <Link href="/">
                <Button variant="ghost" className="w-full justify-start text-muted-foreground">
                  <Home className="h-4 w-4 mr-2" />
                  Home
                </Button>
              </Link>
              <Button
                variant="ghost"
                className={`justify-start ${activeTab === 'users' ? 'bg-violet-500/10 text-violet-600 font-medium' : 'text-muted-foreground'}`}
                onClick={() => { setActiveTab('users'); setIsSidebarOpen(false); }}
              >
                <Users className="h-4 w-4 mr-2" />
                Users
                <Badge variant="secondary" className="ml-auto">
                  {users.length}
                </Badge>
              </Button>
              <Button 
                variant="ghost" 
                className={`justify-start ${activeTab === 'verifiers' ? 'bg-violet-500/10 text-violet-600 font-medium' : 'text-muted-foreground'}`}
                onClick={() => { setActiveTab('verifiers'); setIsSidebarOpen(false); }}
              >
                <ShieldAlert className="h-4 w-4 mr-2" />
                Verifiers
                {pendingVerifiers > 0 && (
                  <Badge variant="destructive" className="ml-auto">
                    {pendingVerifiers}
                  </Badge>
                )}
              </Button>
              <Button 
                variant="ghost" 
                className={`justify-start ${activeTab === 'reports' ? 'bg-violet-500/10 text-violet-600 font-medium' : 'text-muted-foreground'}`}
                onClick={() => { setActiveTab('reports'); setIsSidebarOpen(false); }}
              >
                <AlertTriangle className="h-4 w-4 mr-2" />
                Abuse Reports
                {pendingReports > 0 && (
                  <Badge variant="destructive" className="ml-auto">
                    {pendingReports}
                  </Badge>
                )}
              </Button>
              <Button 
                variant="ghost" 
                className={`justify-start ${activeTab === 'notifications' ? 'bg-violet-500/10 text-violet-600 font-medium' : 'text-muted-foreground'}`}
                onClick={() => { setActiveTab('notifications'); setIsSidebarOpen(false); }}
              >
                <Bell className="h-4 w-4 mr-2" />
                Notifications
              </Button>
              <Button 
                variant="ghost" 
                className={`justify-start ${activeTab === 'settings' ? 'bg-violet-500/10 text-violet-600 font-medium' : 'text-muted-foreground'}`}
                onClick={() => { setActiveTab('settings'); setIsSidebarOpen(false); }}
              >
                <Settings className="h-4 w-4 mr-2" />
                Settings
              </Button>
            </nav>
          </aside>

          {/* Main Content */}
          <main className="flex-1 p-4 md:p-6 w-full max-w-full overflow-hidden">
            <div className="max-w-7xl mx-auto space-y-6">
              
              {activeTab === 'users' && (
                <>
                  <div className="mb-6 flex items-center justify-between">
                    <div>
                      <h1 className="text-2xl font-bold">User Management</h1>
                      <p className="text-muted-foreground">
                        Overview of the platform and registered users
                      </p>
                    </div>
                  </div>
                  {stats && <StatsOverview stats={stats} />}
                  <Card className="mt-6 border-slate-200 dark:border-slate-800 shadow-sm">
                    <CardHeader className="bg-slate-50/50 dark:bg-slate-900/50 border-b">
                      <CardTitle className="text-lg flex items-center gap-2">
                        <Users className="h-5 w-5 text-violet-500" />
                        Registered Users
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="p-0">
                      <UsersTable users={users} />
                    </CardContent>
                  </Card>
                </>
              )}

              {activeTab === 'verifiers' && (
                <>
                  <div className="mb-6">
                    <h1 className="text-2xl font-bold">Verifier Requests</h1>
                    <p className="text-muted-foreground">
                      Review and manage organization verifier registrations
                    </p>
                  </div>
                  <Card className="border-slate-200 dark:border-slate-800 shadow-sm">
                    <CardContent className="p-0">
                      <VerifiersTable
                        requests={verifierRequests}
                        onRequestHandled={fetchData}
                      />
                    </CardContent>
                  </Card>
                </>
              )}

              {activeTab === 'reports' && (
                <>
                  <div className="mb-6">
                    <h1 className="text-2xl font-bold">Abuse Reports</h1>
                    <p className="text-muted-foreground">
                      Investigate and resolve reported fraudulent certificates
                    </p>
                  </div>
                  <Card className="border-slate-200 dark:border-slate-800 shadow-sm">
                    <CardContent className="p-0">
                      <AbuseReports
                        reports={abuseReports}
                        onReportResolved={fetchData}
                      />
                    </CardContent>
                  </Card>
                </>
              )}

              {activeTab === 'notifications' && (
                <>
                  <div className="mb-6">
                    <h1 className="text-2xl font-bold">Notifications</h1>
                    <p className="text-muted-foreground">
                      View your recent alerts and messages
                    </p>
                  </div>
                  <NotificationList />
                </>
              )}

              {activeTab === 'settings' && (
                <>
                  <div className="mb-6">
                    <h1 className="text-2xl font-bold">Settings</h1>
                    <p className="text-muted-foreground">
                      Manage your profile and account preferences
                    </p>
                  </div>
                  <Card className="max-w-3xl border-slate-200 dark:border-slate-800 shadow-sm">
                    <CardHeader className="bg-slate-50/50 dark:bg-slate-900/50 border-b">
                      <CardTitle className="text-lg flex items-center gap-2">
                        <Settings className="h-5 w-5 text-violet-500" />
                        Profile Information
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-6 pt-6">
                      <div className="flex items-center gap-6">
                        <div className="relative group cursor-pointer">
                          <input
                            type="file"
                            accept="image/*"
                            onChange={handleImageUpload}
                            disabled={uploadingImage}
                            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
                            title="Upload new profile picture"
                          />
                          <div className="flex h-24 w-24 overflow-hidden items-center justify-center rounded-full bg-violet-500/10 text-violet-600 text-4xl font-bold border-2 border-violet-500/20 group-hover:opacity-80 transition-opacity">
                            {session?.user?.image ? (
                              <img src={session.user.image} alt="Profile" className="h-full w-full object-cover" />
                            ) : (
                              (session?.user?.name || session?.user?.email || 'A').charAt(0).toUpperCase()
                            )}
                          </div>
                          <div className="absolute inset-0 flex items-center justify-center rounded-full bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none">
                            {uploadingImage ? (
                              <Loader2 className="h-6 w-6 text-white animate-spin" />
                            ) : (
                              <Camera className="h-6 w-6 text-white" />
                            )}
                          </div>
                        </div>
                        <div className="space-y-1">
                          <h3 className="text-xl font-medium">{session?.user?.name || "Administrator"}</h3>
                          <p className="text-muted-foreground">{session?.user?.email}</p>
                        </div>
                      </div>
                      <div className="grid gap-4 pt-4 border-t border-slate-200 dark:border-slate-800">
                        <div>
                          <p className="text-sm font-medium text-muted-foreground mb-1">Full Name</p>
                          <p className="text-foreground">{session?.user?.name || 'Not provided'}</p>
                        </div>
                        <div>
                          <p className="text-sm font-medium text-muted-foreground mb-1">Email Address</p>
                          <p className="text-foreground">{session?.user?.email}</p>
                        </div>
                        <div>
                          <p className="text-sm font-medium text-muted-foreground mb-1">Role</p>
                          <p className="capitalize text-violet-600 font-medium">Administrator</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </>
              )}

            </div>
          </main>
        </div>

        {/* Mobile Sidebar Overlay */}
        {isSidebarOpen && (
          <div
            className="fixed inset-0 z-20 bg-black/50 md:hidden"
            onClick={() => setIsSidebarOpen(false)}
          />
        )}
      </div>
    </RoleGuard>
  );
}
