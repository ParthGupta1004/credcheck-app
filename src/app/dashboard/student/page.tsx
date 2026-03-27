'use client';

import { useState } from 'react';
import { useSession, signOut } from 'next-auth/react';
import { useRouter } from 'next/navigation';
import { SidebarProvider, Sidebar, SidebarContent, SidebarHeader, SidebarFooter, SidebarMenu, SidebarMenuItem, SidebarMenuButton, SidebarInset, SidebarSeparator, SidebarGroup, SidebarGroupLabel, SidebarGroupContent } from '@/components/ui/sidebar';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { CertificateList } from '@/components/student/certificate-list';
import { RoleGuard } from '@/components/auth/role-guard';
import { NotificationList } from '@/components/notifications/notification-list';
import { NotificationBell } from '@/components/notifications/notification-bell';
import { useToast } from '@/hooks/use-toast';
import {
  FileText,
  Settings,
  User,
  LogOut,
  GraduationCap,
  Building2,
  Calendar,
  Edit2,
  Loader2,
  Shield,
  Home,
  Key,
  Eye,
  EyeOff,
  Bell,
  Camera,
} from 'lucide-react';
import Link from 'next/link';

export default function StudentDashboard() {
  const { data: session, update } = useSession();
  const router = useRouter();
  
  const [profileDialogOpen, setProfileDialogOpen] = useState(false);
  const [passwordDialogOpen, setPasswordDialogOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [uploadingImage, setUploadingImage] = useState(false);
  const [savingPassword, setSavingPassword] = useState(false);
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [activeTab, setActiveTab] = useState<'certificates' | 'profile' | 'notifications'>('certificates');
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });
  const { toast } = useToast();

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

      await update({ image: fileUrl });
      toast({ title: "Success", description: "Profile image updated!" });
    } catch (error) {
      toast({ title: "Error", description: "Failed to upload image", variant: "destructive" });
    } finally {
      setUploadingImage(false);
    }
  };

  const user = {
    id: session?.user?.id || '',
    name: session?.user?.name || '',
    email: session?.user?.email || '',
    role: session?.user?.role || 'student',
    college: session?.user?.college || '',
    degree: session?.user?.degree || '',
    batch: session?.user?.batch || '',
    verified: session?.user?.verified || false,
  };

  const [profileForm, setProfileForm] = useState({
    name: user.name,
    college: user.college || '',
    degree: user.degree || '',
    batch: user.batch || '',
  });

  const handleSaveProfile = async () => {
    setSaving(true);
    try {
      const response = await fetch('/api/user/profile', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: profileForm.name,
          college: profileForm.college,
          degree: profileForm.degree,
          batch: profileForm.batch,
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to update profile');
      }

      setProfileDialogOpen(false);
      toast({
        title: 'Profile updated',
        description: 'Your profile has been updated successfully.',
      });

      // Update the NextAuth session explicitly
      await update({
        user: {
          ...session?.user,
          name: profileForm.name,
          college: profileForm.college,
          degree: profileForm.degree,
          batch: profileForm.batch,
        }
      });
      router.refresh();
    } catch (error) {
      console.error('Error saving profile:', error);
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to update profile',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleSignOut = async () => {
    await signOut({ redirect: false });
    router.push('/');
  };

  const handleChangePassword = async () => {
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      toast({
        title: 'Error',
        description: 'New passwords do not match',
        variant: 'destructive',
      });
      return;
    }

    if (passwordForm.newPassword.length < 6) {
      toast({
        title: 'Error',
        description: 'New password must be at least 6 characters',
        variant: 'destructive',
      });
      return;
    }

    setSavingPassword(true);
    try {
      const response = await fetch('/api/user/password', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          currentPassword: passwordForm.currentPassword,
          newPassword: passwordForm.newPassword,
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to change password');
      }

      setPasswordDialogOpen(false);
      setPasswordForm({
        currentPassword: '',
        newPassword: '',
        confirmPassword: '',
      });
      toast({
        title: 'Password changed',
        description: 'Your password has been changed successfully.',
      });
    } catch (error) {
      console.error('Error changing password:', error);
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to change password',
        variant: 'destructive',
      });
    } finally {
      setSavingPassword(false);
    }
  };

  const menuItems = [
    {
      icon: FileText,
      label: 'Certificates',
      id: 'certificates' as const,
    },
  ];

  return (
    <RoleGuard allowedRole="student">
      <SidebarProvider>
        <Sidebar>
          <SidebarHeader className="border-b px-4 py-4">
            <Link href="/" className="flex items-center gap-2">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                <Shield className="h-5 w-5" />
              </div>
              <div>
                <h1 className="text-lg font-semibold">CredCheck</h1>
                <p className="text-xs text-muted-foreground">Student Portal</p>
              </div>
            </Link>
          </SidebarHeader>

          <SidebarContent>
            <SidebarGroup>
              <SidebarGroupContent>
                <SidebarMenu>
                  <SidebarMenuItem>
                    <SidebarMenuButton asChild>
                      <Link href="/">
                        <Home className="h-4 w-4" />
                        <span>Home</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                  {menuItems.map((item) => (
                    <SidebarMenuItem key={item.id}>
                      <SidebarMenuButton
                        isActive={activeTab === item.id}
                        onClick={() => setActiveTab(item.id)}
                      >
                        <item.icon className="h-4 w-4" />
                        <span>{item.label}</span>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                  <SidebarMenuItem>
                    <SidebarMenuButton
                      isActive={activeTab === 'notifications'}
                      onClick={() => setActiveTab('notifications')}
                    >
                      <Bell className="h-4 w-4" />
                      <span>Notifications</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                  <SidebarMenuItem>
                    <SidebarMenuButton
                      isActive={activeTab === 'profile'}
                      onClick={() => setActiveTab('profile')}
                    >
                      <Settings className="h-4 w-4" />
                      <span>Settings</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </SidebarContent>


          <SidebarFooter className="border-t p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-emerald-500 text-white overflow-hidden">
                {session?.user?.image ? (
                  <img src={session.user.image} alt="Profile" className="h-full w-full object-cover" />
                ) : (
                  <User className="h-4 w-4" />
                )}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{user.name}</p>
                <p className="text-xs text-muted-foreground truncate">{user.email}</p>
              </div>
            </div>
          </SidebarFooter>
        </Sidebar>

        <SidebarInset>
          <div className="flex flex-col min-h-screen">
            {/* Header */}
            <header className="sticky top-0 z-10 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
              <div className="flex h-14 items-center gap-4 px-6">
                <h2 className="text-lg font-semibold">
                  {activeTab === 'certificates' ? 'My Certificates' : activeTab === 'notifications' ? 'Notifications' : 'Settings'}
                </h2>
                <div className="flex items-center gap-2 ml-auto">
                  <div className="flex h-8 w-8 items-center justify-center rounded-full bg-emerald-500/10 text-emerald-500 font-bold overflow-hidden">
                    {session?.user?.image ? (
                      <img src={session.user.image} alt="Profile" className="h-full w-full object-cover" />
                    ) : (
                      (user.name || 'S').charAt(0).toUpperCase()
                    )}
                  </div>
                  <Link href="/">
                    <Button variant="ghost" size="icon" title="Home">
                      <Home className="h-5 w-5" />
                    </Button>
                  </Link>
                  <Button 
                    variant="ghost" 
                    size="icon" 
                    title="Notifications"
                    onClick={() => setActiveTab('notifications')}
                  >
                    <NotificationBell className="h-5 w-5" />
                  </Button>
                  <Button 
                    variant="ghost" 
                    size="icon" 
                    onClick={handleSignOut} 
                    title="Logout"
                  >
                    <LogOut className="h-5 w-5" />
                  </Button>
                </div>
              </div>
            </header>

            {/* Main Content */}
            <main className="flex-1 p-6">
              {activeTab === 'certificates' && (
                <CertificateList studentId={user.id} />
              )}

              {activeTab === 'notifications' && (
                <div className="max-w-2xl mx-auto space-y-6">
                  <div className="mb-6">
                    <p className="text-muted-foreground">
                      View your recent alerts and messages
                    </p>
                  </div>
                  <NotificationList />
                </div>
              )}

              {activeTab === 'profile' && (
                <div className="max-w-2xl mx-auto space-y-6">
                  <Card>
                    <CardHeader>
                      <div className="flex items-center justify-between">
                        <div>
                          <CardTitle>Profile Information</CardTitle>
                          <CardDescription>
                            Update your personal and academic information
                          </CardDescription>
                        </div>
                        <Dialog open={profileDialogOpen} onOpenChange={setProfileDialogOpen}>
                          <DialogTrigger asChild>
                            <Button variant="outline" size="sm">
                              <Edit2 className="h-4 w-4 mr-2" />
                              Edit Profile
                            </Button>
                          </DialogTrigger>
                          <DialogContent className="sm:max-w-md">
                            <DialogHeader>
                              <DialogTitle>Edit Profile</DialogTitle>
                              <DialogDescription>
                                Update your profile information below.
                              </DialogDescription>
                            </DialogHeader>
                            <div className="space-y-4 py-4">
                              <div className="space-y-2">
                                <Label htmlFor="name">Full Name</Label>
                                <Input
                                  id="name"
                                  value={profileForm.name}
                                  onChange={(e) =>
                                    setProfileForm((prev) => ({
                                      ...prev,
                                      name: e.target.value,
                                    }))
                                  }
                                />
                              </div>
                              <div className="space-y-2">
                                <Label htmlFor="college">
                                  <div className="flex items-center gap-1">
                                    <Building2 className="h-3.5 w-3.5" />
                                    College / University
                                  </div>
                                </Label>
                                <Input
                                  id="college"
                                  placeholder="e.g., Stanford University"
                                  value={profileForm.college}
                                  onChange={(e) =>
                                    setProfileForm((prev) => ({
                                      ...prev,
                                      college: e.target.value,
                                    }))
                                  }
                                />
                              </div>
                              <div className="space-y-2">
                                <Label htmlFor="degree">
                                  <div className="flex items-center gap-1">
                                    <GraduationCap className="h-3.5 w-3.5" />
                                    Degree / Program
                                  </div>
                                </Label>
                                <Input
                                  id="degree"
                                  placeholder="e.g., Computer Science"
                                  value={profileForm.degree}
                                  onChange={(e) =>
                                    setProfileForm((prev) => ({
                                      ...prev,
                                      degree: e.target.value,
                                    }))
                                  }
                                />
                              </div>
                              <div className="space-y-2">
                                <Label htmlFor="batch">
                                  <div className="flex items-center gap-1">
                                    <Calendar className="h-3.5 w-3.5" />
                                    Batch / Year
                                  </div>
                                </Label>
                                <Input
                                  id="batch"
                                  placeholder="e.g., 2024"
                                  value={profileForm.batch}
                                  onChange={(e) =>
                                    setProfileForm((prev) => ({
                                      ...prev,
                                      batch: e.target.value,
                                    }))
                                  }
                                />
                              </div>
                            </div>
                            <DialogFooter>
                              <Button
                                variant="outline"
                                onClick={() => setProfileDialogOpen(false)}
                                disabled={saving}
                              >
                                Cancel
                              </Button>
                              <Button onClick={handleSaveProfile} disabled={saving}>
                                {saving && (
                                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                                )}
                                Save Changes
                              </Button>
                            </DialogFooter>
                          </DialogContent>
                        </Dialog>
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-6">
                      <div className="flex items-center gap-6 mb-6">
                        <div className="relative group cursor-pointer">
                          <input
                            type="file"
                            accept="image/*"
                            onChange={handleImageUpload}
                            disabled={uploadingImage}
                            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
                            title="Upload new profile picture"
                          />
                          <div className="flex h-24 w-24 overflow-hidden items-center justify-center rounded-full bg-emerald-500/10 text-emerald-500 text-4xl font-bold border-2 border-emerald-500/20 group-hover:opacity-80 transition-opacity">
                            {session?.user?.image ? (
                              <img src={session.user.image} alt="Profile" className="h-full w-full object-cover" />
                            ) : (
                              (user.name || 'S').charAt(0).toUpperCase()
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
                          <h3 className="text-xl font-medium">{user.name}</h3>
                          <p className="text-muted-foreground">{user.email}</p>
                        </div>
                      </div>
                      <div className="grid gap-4 md:grid-cols-2 border-t pt-6">
                        <div className="space-y-2">
                          <Label className="text-muted-foreground text-sm">Full Name</Label>
                          <p className="font-medium">{user.name}</p>
                        </div>
                        <div className="space-y-2">
                          <Label className="text-muted-foreground text-sm">Email</Label>
                          <p className="font-medium">{user.email}</p>
                        </div>
                        <div className="space-y-2">
                          <Label className="text-muted-foreground text-sm flex items-center gap-1">
                            <Building2 className="h-3.5 w-3.5" />
                            College / University
                          </Label>
                          <p className="font-medium">{user.college || 'Not set'}</p>
                        </div>
                        <div className="space-y-2">
                          <Label className="text-muted-foreground text-sm flex items-center gap-1">
                            <GraduationCap className="h-3.5 w-3.5" />
                            Degree / Program
                          </Label>
                          <p className="font-medium">{user.degree || 'Not set'}</p>
                        </div>
                        <div className="space-y-2">
                          <Label className="text-muted-foreground text-sm flex items-center gap-1">
                            <Calendar className="h-3.5 w-3.5" />
                            Batch / Year
                          </Label>
                          <p className="font-medium">{user.batch || 'Not set'}</p>
                        </div>
                        <div className="space-y-2">
                          <Label className="text-muted-foreground text-sm">Account Status</Label>
                          <div className="flex items-center gap-2">
                            {user.verified ? (
                              <Badge className="bg-emerald-500">Verified</Badge>
                            ) : (
                              <Badge variant="secondary">Unverified</Badge>
                            )}
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader>
                      <CardTitle>Security</CardTitle>
                      <CardDescription>
                        Manage your account security settings
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <Dialog open={passwordDialogOpen} onOpenChange={setPasswordDialogOpen}>
                        <DialogTrigger asChild>
                          <Button variant="outline" className="gap-2">
                            <Key className="h-4 w-4" />
                            Change Password
                          </Button>
                        </DialogTrigger>
                        <DialogContent className="sm:max-w-md">
                          <DialogHeader>
                            <DialogTitle>Change Password</DialogTitle>
                            <DialogDescription>
                              Enter your current password and choose a new one.
                            </DialogDescription>
                          </DialogHeader>
                          <div className="space-y-4 py-4">
                            <div className="space-y-2">
                              <Label htmlFor="currentPassword">Current Password</Label>
                              <div className="relative">
                                <Input
                                  id="currentPassword"
                                  type={showCurrentPassword ? 'text' : 'password'}
                                  value={passwordForm.currentPassword}
                                  onChange={(e) =>
                                    setPasswordForm((prev) => ({
                                      ...prev,
                                      currentPassword: e.target.value,
                                    }))
                                  }
                                  placeholder="Enter current password"
                                />
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="icon"
                                  className="absolute right-0 top-0 h-full"
                                  onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                                >
                                  {showCurrentPassword ? (
                                    <EyeOff className="h-4 w-4" />
                                  ) : (
                                    <Eye className="h-4 w-4" />
                                  )}
                                </Button>
                              </div>
                            </div>
                            <div className="space-y-2">
                              <Label htmlFor="newPassword">New Password</Label>
                              <div className="relative">
                                <Input
                                  id="newPassword"
                                  type={showNewPassword ? 'text' : 'password'}
                                  value={passwordForm.newPassword}
                                  onChange={(e) =>
                                    setPasswordForm((prev) => ({
                                      ...prev,
                                      newPassword: e.target.value,
                                    }))
                                  }
                                  placeholder="Enter new password"
                                />
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="icon"
                                  className="absolute right-0 top-0 h-full"
                                  onClick={() => setShowNewPassword(!showNewPassword)}
                                >
                                  {showNewPassword ? (
                                    <EyeOff className="h-4 w-4" />
                                  ) : (
                                    <Eye className="h-4 w-4" />
                                  )}
                                </Button>
                              </div>
                            </div>
                            <div className="space-y-2">
                              <Label htmlFor="confirmPassword">Confirm New Password</Label>
                              <Input
                                id="confirmPassword"
                                type="password"
                                value={passwordForm.confirmPassword}
                                onChange={(e) =>
                                  setPasswordForm((prev) => ({
                                    ...prev,
                                    confirmPassword: e.target.value,
                                  }))
                                }
                                placeholder="Confirm new password"
                              />
                            </div>
                          </div>
                          <DialogFooter>
                            <Button
                              variant="outline"
                              onClick={() => setPasswordDialogOpen(false)}
                              disabled={savingPassword}
                            >
                              Cancel
                            </Button>
                            <Button
                              onClick={handleChangePassword}
                              disabled={savingPassword}
                            >
                              {savingPassword && (
                                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                              )}
                              Change Password
                            </Button>
                          </DialogFooter>
                        </DialogContent>
                      </Dialog>
                    </CardContent>
                  </Card>
                </div>
              )}
            </main>
          </div>
        </SidebarInset>
      </SidebarProvider>
    </RoleGuard>
  );
}
