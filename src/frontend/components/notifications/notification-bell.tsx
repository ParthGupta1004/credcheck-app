'use client';

import { useState, useEffect } from 'react';
import { Bell } from 'lucide-react';

interface NotificationBellProps {
  className?: string; // Additional classes for the Bell icon sizing if needed
}

export function NotificationBell({ className = "h-5 w-5" }: NotificationBellProps) {
  const [unreadCount, setUnreadCount] = useState(0);

  useEffect(() => {
    const fetchUnreadCount = async () => {
      try {
        const res = await fetch('/api/notifications');
        if (res.ok) {
          const data = await res.json();
          setUnreadCount(data.unreadCount);
        }
      } catch (e) {
        console.error("Failed to fetch notifications unread count:", e);
      }
    };
    
    fetchUnreadCount();
    
    // Poll every 30 seconds for live updates
    const interval = setInterval(fetchUnreadCount, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="relative flex items-center justify-center">
      <Bell className={className} />
      {unreadCount > 0 && (
        <span className="absolute -top-1.5 -right-1.5 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white shadow-sm ring-2 ring-background">
          {unreadCount > 99 ? '99+' : unreadCount}
        </span>
      )}
    </div>
  );
}
