import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const status = searchParams.get('status') || 'all';
    const search = searchParams.get('search') || '';
    const verifierEmail = searchParams.get('verifierEmail');

    if (!verifierEmail) {
      return NextResponse.json(
        { error: 'Verifier email is required' },
        { status: 400 }
      );
    }

    // Build the where clause
    const where: {
      verifierEmail: string;
      status?: string;
      OR?: Array<{
        title?: { contains: string };
        organization?: { contains: string };
        student?: {
          OR: Array<{
            name?: { contains: string };
            email?: { contains: string };
          }>;
        };
      }>;
    } = {
      verifierEmail,
    };

    if (status !== 'all') {
      where.status = status;
    }

    if (search) {
      where.OR = [
        { title: { contains: search } },
        { organization: { contains: search } },
        {
          student: {
            OR: [
              { name: { contains: search } },
              { email: { contains: search } },
            ],
          },
        },
      ];
    }

    const certificates = await db.certificate.findMany({
      where,
      include: {
        student: {
          select: {
            id: true,
            name: true,
            email: true,
            college: true,
            degree: true,
            batch: true,
          },
        },
        verifier: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    // Get statistics
    const stats = await db.certificate.groupBy({
      by: ['status'],
      where: { verifierEmail },
      _count: {
        id: true,
      },
    });

    const statistics = {
      total: 0,
      pending: 0,
      verified: 0,
      rejected: 0,
    };

    stats.forEach((stat) => {
      statistics.total += stat._count.id;
      if (stat.status === 'pending') statistics.pending = stat._count.id;
      if (stat.status === 'verified') statistics.verified = stat._count.id;
      if (stat.status === 'rejected') statistics.rejected = stat._count.id;
    });

    return NextResponse.json({
      certificates,
      statistics,
    });
  } catch (error) {
    console.error('Error fetching verifications:', error);
    return NextResponse.json(
      { error: 'Failed to fetch verifications' },
      { status: 500 }
    );
  }
}
