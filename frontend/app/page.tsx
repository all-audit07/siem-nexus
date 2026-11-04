import Navbar from "@/components/Navbar";
import Hero from "@/components/Hero";
import Features from "@/components/Features";
import { WovenLightHero } from "@/components/ui/woven-light-hero";
import SocialProof from "@/components/SocialProof";
import Pricing from "@/components/Pricing";
import FAQ from "@/components/FAQ";
import CTAWithTextMarquee from "@/components/ui/cta-with-text-marquee";
import Footer from "@/components/Footer";

export default function LandingPage() {
  return (
    <main className="bg-[#020817] text-[#E2E8F0]">
      <Navbar />
      <Hero />
      <Features />
      <WovenLightHero />
      <SocialProof />
      <Pricing />
      <FAQ />
      <CTAWithTextMarquee />
      <Footer />
    </main>
  );
}
