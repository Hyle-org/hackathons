"use client";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Anton } from "next/font/google";

const anton = Anton({
  weight: "400",
  subsets: ["latin"],
});

export default function FaucetPage() {
  const [username, setUsername] = useState("");
  const [selectedToken, setSelectedToken] = useState("hyllar");

  return (
    <div className="min-h-screen flex items-center justify-center bg-[url('/images/satelliteBG.jpg')] p-8 animate-[floatSlow_120s_linear_infinite] sm:animate-[floatSlow_150s_linear_infinite] md:animate-[floatSlow_180s_linear_infinite] lg:animate-[floatSlow_210s_linear_infinite]">
      <div
        className={`w-full max-w-md p-8 space-y-6 aero-window rounded-[1rem] rounded-tr-[0.7rem] ${anton.className}`}
      >
        <Tabs defaultValue="faucet" className="w-full">
          <TabsList className="grid w-full grid-cols-5 gap-2">
            <TabsTrigger value="register">Register</TabsTrigger>
            <TabsTrigger value="faucet">Faucet</TabsTrigger>
            <TabsTrigger value="transfer">Transfer</TabsTrigger>
            <TabsTrigger value="approve">Approve</TabsTrigger>
            <TabsTrigger value="swap">Swap</TabsTrigger>
          </TabsList>
        </Tabs>

        <div className="space-y-4">
          <div className="text-center text-[1rem] tracking-wide">
            Select a token:
          </div>
          <Select value={selectedToken} onValueChange={setSelectedToken}>
            <SelectTrigger className="w-full">
              <SelectValue placeholder="Select token" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="hyllar">Hyllar</SelectItem>
              <SelectItem value="hyllar2">Hyllar2</SelectItem>
            </SelectContent>
          </Select>
          <div className="text-center text-sm tracking-[0.7px] opacity-50">
            Selected token: {selectedToken}
          </div>
          <div className="text-[1.1rem] font-medium tracking-[0.4px]">
            Username:
          </div>
          <div className="relative">
            <Input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full pr-24 border-[rgba(255,255,255,0.3)] focus:border-[rgba(255,255,255,0.5)] placeholder-white focus:text-white transition-colors duration-200"
            />
            <span className="absolute  tracking-[0.3px] right-3 top-1/2 -translate-y-1/2 text-sm opacity-50">
              .hydentity
            </span>
          </div>
          <Button className="w-full tracking-[0.3px] hover:bg-[#e0492e] text-[1rem] text-gray-600 hover:text-white transition-colors duration-200">
            Faucet 10 {selectedToken} to {username}.hydentity
          </Button>
          <div className="space-y-1 text-sm tracking-[0.2px]">
            <div>Total supply: 10000000000</div>
            <div className="opacity-50">
              Balance: Account {username}.hydentity not found
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
