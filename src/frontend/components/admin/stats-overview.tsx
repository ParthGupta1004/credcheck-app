"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Users, FileCheck, ShieldAlert, Clock } from "lucide-react";

interface Stats {
  totalUsers: number;
  totalCertificates: number;
  totalVerifiers: number;
  pendingRequests: number;
}

interface StatsOverviewProps {
  stats: Stats;
}

export function StatsOverview({ stats }: StatsOverviewProps) {
  const statsCards = [
    {
      title: "Total Users",
      value: stats.totalUsers,
      icon: Users,
      description: "Registered platform users",
      color: "text-blue-600",
      bgColor: "bg-blue-50",
    },
    {
      title: "Certificates",
      value: stats.totalCertificates,
      icon: FileCheck,
      description: "Total certificates uploaded",
      color: "text-green-600",
      bgColor: "bg-green-50",
    },
    {
      title: "Verifiers",
      value: stats.totalVerifiers,
      icon: ShieldAlert,
      description: "Active verifiers",
      color: "text-purple-600",
      bgColor: "bg-purple-50",
    },
    {
      title: "Pending Requests",
      value: stats.pendingRequests,
      icon: Clock,
      description: "Awaiting review",
      color: "text-orange-600",
      bgColor: "bg-orange-50",
    },
  ];

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      {statsCards.map((stat) => (
        <Card key={stat.title}>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{stat.title}</CardTitle>
            <div className={`rounded-lg p-2 ${stat.bgColor}`}>
              <stat.icon className={`h-4 w-4 ${stat.color}`} />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stat.value.toLocaleString()}</div>
            <p className="text-xs text-muted-foreground">{stat.description}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
