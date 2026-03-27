'use client';

import { useState } from 'react';
import { useSession, signOut } from 'next-auth/react';
import { useRouter } from 'next/navigation';
import { VerificationRequests } from '@/components/verifier/verification-requests';
import { RoleGuard } from '@/components/auth/role-guard';
import { NotificationList } from '@/components/notifications/notification-list';
import { NotificationBell } from '@/components/notifications/notification-bell';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Bell,
  Settings,
  LogOut,
  Shield,
  Menu,
  Home,
  User,
  Camera,
  Loader2,
} from 'lucide-react';
import Link from 'next/link';
import { useToast } from '@/hooks/use-toast';

export default function VerifierDashboard() {
  const { data: session, update: updateSession } = useSession();
  const router = useRouter();
  const { toast } = useToast();
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<'requests' | 'notifications' | 'settings'>('requests');
  const [uploadingImage, setUploadingImage] = useState(false);

  const verifierEmail = session?.user?.email || '';

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
  
  const handleSignOut = async () => {
    await signOut({ redirect: false });
    router.push('/');
  };

  return (
    <RoleGuard allowedRole="verifier">
      <div className="min-h-screen bg-background">
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
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                <Shield className="h-4 w-4" />
              </div>
              <span className="font-bold text-lg">CredCheck</span>
            </Link>
            <Badge className="bg-amber-500 ml-2">Verifier</Badge>

            <div className="ml-auto flex items-center gap-2">
              <div className="hidden sm:flex items-center gap-2 mr-4">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-amber-500/10 text-amber-500 font-bold overflow-hidden">
                  {session?.user?.image ? (
                    <img src={session.user.image} alt="Profile" className="h-full w-full object-cover" />
                  ) : (
                    (session?.user?.name || 'V').charAt(0).toUpperCase()
                  )}
                </div>
              </div>
              <Link href="/">
                <Button variant="ghost" size="icon" title="Home">
                  <Home className="h-5 w-5" />
                </Button>
              </Link>
              <Button variant="ghost" size="icon" title="Notifications" onClick={() => setActiveTab('notifications')}>
                <NotificationBell className="h-5 w-5" />
              </Button>
              <Button variant="ghost" size="icon" onClick={handleSignOut} title="Logout">
                <LogOut className="h-5 w-5" />
              </Button>
            </div>
          </div>
        </header>

        <div className="flex">
          {/* Sidebar */}
          <aside
            className={`
              fixed inset-y-0 left-0 z-30 w-64 transform border-r bg-background
              transition-transform duration-200 ease-in-out md:translate-x-0 md:static
              ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'}
              pt-16 md:pt-0
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
                className={`justify-start ${activeTab === 'requests' ? 'bg-amber-500/10 text-amber-600' : 'text-muted-foreground'}`}
                onClick={() => { setActiveTab('requests'); setIsSidebarOpen(false); }}
              >
                <Shield className="h-4 w-4 mr-2" />
                Verification Requests
              </Button>
              <Button 
                variant="ghost" 
                className={`justify-start ${activeTab === 'notifications' ? 'bg-amber-500/10 text-amber-600' : 'text-muted-foreground'}`}
                onClick={() => { setActiveTab('notifications'); setIsSidebarOpen(false); }}
              >
                <Bell className="h-4 w-4 mr-2" />
                Notifications
              </Button>
              <Button 
                variant="ghost" 
                className={`justify-start ${activeTab === 'settings' ? 'bg-amber-500/10 text-amber-600' : 'text-muted-foreground'}`}
                onClick={() => { setActiveTab('settings'); setIsSidebarOpen(false); }}
              >
                <Settings className="h-4 w-4 mr-2" />
                Settings
              </Button>
            </nav>
          </aside>

          {/* Main Content */}
          <main className="flex-1 p-4 md:p-6">
            <div className="max-w-7xl mx-auto">
              {activeTab === 'requests' && (
                <>
                  <div className="mb-6">
                    <h1 className="text-2xl font-bold">Verification Dashboard</h1>
                    <p className="text-muted-foreground">
                      Review and process certificate verification requests
                    </p>
                  </div>
                  <VerificationRequests verifierEmail={verifierEmail} />
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
                  <Card className="max-w-3xl">
                    <CardHeader>
                      <CardTitle>Profile Information</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-6">
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
                          <div className="flex h-24 w-24 items-center justify-center rounded-full bg-amber-500/10 text-amber-500 text-4xl font-bold border-2 border-amber-500/20 overflow-hidden group-hover:opacity-80 transition-opacity">
                            {session?.user?.image ? (
                              <img src={session.user.image} alt="Profile" className="h-full w-full object-cover" />
                            ) : (
                              (session?.user?.name || 'V').charAt(0).toUpperCase()
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
                          <h3 className="text-xl font-medium">{session?.user?.name || 'Verifier Name'}</h3>
                          <p className="text-muted-foreground">{session?.user?.email}</p>
                        </div>
                      </div>
                      <div className="grid gap-4 pt-4 border-t">
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
                          <p className="capitalize text-amber-600 font-medium">Verifier</p>
                        </div>
                      </div>
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
