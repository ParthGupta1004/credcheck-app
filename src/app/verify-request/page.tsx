import { Metadata } from "next";
import { Suspense } from "react";
import { VerifierRequestForm } from "@/components/auth/verifier-request-form";
import { PreviousRequestsList } from "@/components/auth/previous-requests-list";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { 
  ShieldCheck, 
  Clock, 
  CheckCircle2, 
  FileCheck, 
  ArrowLeft 
} from "lucide-react";

export const metadata: Metadata = {
  title: "Become a Verifier | CredCheck",
  description: "Apply to become a certificate verifier on CredCheck. Organizations can verify and authenticate certificates for students.",
};

const processSteps = [
  {
    icon: FileCheck,
    title: "Submit Application",
    description: "Fill out the form with your organization details and submit your request.",
  },
  {
    icon: Clock,
    title: "Review Process",
    description: "Our team reviews your application within 2-3 business days.",
  },
  {
    icon: CheckCircle2,
    title: "Get Approved",
    description: "Once approved, you can verify certificates for students worldwide.",
  },
];

export default function VerifyRequestPage() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-background to-muted/20">
      {/* Header */}
      <header className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60 sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <a href="/" className="flex items-center gap-2">
              <ShieldCheck className="h-8 w-8 text-primary" />
              <span className="text-xl font-bold">CredCheck</span>
            </a>
            <Button variant="ghost" asChild>
              <a href="/login">
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back to Login
              </a>
            </Button>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        {/* Hero Section */}
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold mb-4">Become a Certificate Verifier</h1>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Join our network of trusted organizations to verify and authenticate certificates for students around the world.
          </p>
        </div>

        {/* Process Steps */}
        <div className="grid md:grid-cols-3 gap-6 mb-12 max-w-4xl mx-auto">
          {processSteps.map((step, index) => (
            <Card key={index} className="text-center">
              <CardContent className="pt-6">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-primary/10 text-primary mb-4">
                  <step.icon className="h-6 w-6" />
                </div>
                <h3 className="font-semibold mb-2">{step.title}</h3>
                <p className="text-sm text-muted-foreground">{step.description}</p>
              </CardContent>
            </Card>
          ))}
        </div>

        <Separator className="max-w-4xl mx-auto mb-12" />

        {/* Main Content */}
        <div className="grid lg:grid-cols-2 gap-8 max-w-6xl mx-auto">
          {/* Form Section */}
          <div className="flex justify-center">
            <Suspense fallback={<div className="w-full max-w-2xl h-96 animate-pulse bg-muted rounded-xl" />}>
              <VerifierRequestForm />
            </Suspense>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Previous Requests */}
            <Suspense fallback={<div className="w-full h-64 animate-pulse bg-muted rounded-xl" />}>
              <PreviousRequestsList />
            </Suspense>

            {/* Info Card */}
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Why Become a Verifier?</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div className="flex items-start gap-3">
                    <CheckCircle2 className="h-5 w-5 text-green-500 mt-0.5 shrink-0" />
                    <div>
                      <p className="font-medium">Build Trust</p>
                      <p className="text-sm text-muted-foreground">
                        Your organization becomes a trusted source for certificate verification.
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <CheckCircle2 className="h-5 w-5 text-green-500 mt-0.5 shrink-0" />
                    <div>
                      <p className="font-medium">Streamlined Process</p>
                      <p className="text-sm text-muted-foreground">
                        Easy-to-use dashboard for managing and verifying certificates.
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <CheckCircle2 className="h-5 w-5 text-green-500 mt-0.5 shrink-0" />
                    <div>
                      <p className="font-medium">Global Recognition</p>
                      <p className="text-sm text-muted-foreground">
                        Students worldwide can benefit from your verified certificates.
                      </p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Requirements Card */}
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Requirements</CardTitle>
                <CardDescription>
                  To become a verifier, you need:
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2 text-sm">
                  <li className="flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 text-green-500 shrink-0" />
                    <span>Official organization email address</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 text-green-500 shrink-0" />
                    <span>Valid organization website</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 text-green-500 shrink-0" />
                    <span>Authority to verify certificates</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 text-green-500 shrink-0" />
                    <span>Active organization in good standing</span>
                  </li>
                </ul>
              </CardContent>
            </Card>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t mt-16">
        <div className="container mx-auto px-4 py-8 text-center text-sm text-muted-foreground">
          <p>
            Need help? Contact us at{" "}
            <a href="mailto:support@credcheck.com" className="text-primary hover:underline">
              support@credcheck.com
            </a>
          </p>
        </div>
      </footer>
    </div>
  );
}
