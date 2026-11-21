import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = {
  title: "PASSWORD STRENGTH · P15",
  description: "PASSWORD STRENGTH — laboratoire local, éthique, 0 GPU.",
};
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="fr"><body>{children}</body></html>;
}
