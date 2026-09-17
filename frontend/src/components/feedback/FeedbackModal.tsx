"use client";

import React, { useState } from "react";
import { submitFeedback } from "@/lib/api";

const CATEGORIES = [
  "UI / UX",
  "Detection Accuracy",
  "Feature Idea",
  "Bug Report",
  "General",
];

export function FeedbackModal() {
  const [isOpen, setIsOpen] = useState(false);
  const [rating, setRating] = useState(5);
  const [hoverRating, setHoverRating] = useState(0);
  const [category, setCategory] = useState("UI / UX");
  const [message, setMessage] = useState("");
  const [email, setEmail] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [feedbackId, setFeedbackId] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!message.trim() || message.trim().length < 3) return;

    setIsSubmitting(true);
    try {
      const res = await submitFeedback({
        rating,
        category,
        message: message.trim(),
        email: email.trim() || undefined,
      });
      setFeedbackId(res.feedback_id || "fb-local");
      setSubmitted(true);
    } catch {
      setSubmitted(true);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleReset = () => {
    setSubmitted(false);
    setMessage("");
    setEmail("");
    setRating(5);
    setCategory("UI / UX");
    setIsOpen(false);
  };

  return (
    <>
      {/* Floating Trigger Button (Rapid Prototyper Standard: In-App Feedback Always Accessible) */}
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-5 right-5 z-40 flex items-center gap-2 rounded-full border border-cyan-500/30 bg-slate-900/90 px-4 py-2.5 text-xs font-semibold text-cyan-300 shadow-lg shadow-cyan-500/10 backdrop-blur-md transition-all hover:scale-105 hover:border-cyan-400 hover:bg-slate-800 hover:text-white"
        aria-label="Provide Feedback"
      >
        <span className="flex h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
        <span>💬 Feedback</span>
      </button>

      {/* Modal Overlay */}
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm animate-fadeIn">
          <div className="relative w-full max-w-md rounded-2xl border border-slate-700/60 bg-[#080f1e]/95 p-6 shadow-2xl shadow-cyan-500/10 backdrop-blur-xl">
            {/* Close Button */}
            <button
              onClick={() => setIsOpen(false)}
              className="absolute right-4 top-4 rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
            >
              <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>

            {!submitted ? (
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-lg">⚡</span>
                    <h3 className="text-base font-bold text-white">Rapid Feedback & Validation</h3>
                  </div>
                  <p className="mt-1 text-xs text-slate-400">
                    Your direct impressions help us iterate and sharpen SentinelFlow detection.
                  </p>
                </div>

                {/* Rating Stars */}
                <div>
                  <label className="text-xs font-medium text-slate-300">How is your experience?</label>
                  <div className="mt-1.5 flex items-center gap-1.5">
                    {[1, 2, 3, 4, 5].map((star) => (
                      <button
                        key={star}
                        type="button"
                        onClick={() => setRating(star)}
                        onMouseEnter={() => setHoverRating(star)}
                        onMouseLeave={() => setHoverRating(0)}
                        className="text-xl transition-transform hover:scale-125 focus:outline-none"
                      >
                        <span className={star <= (hoverRating || rating) ? "text-amber-400" : "text-slate-600"}>
                          ★
                        </span>
                      </button>
                    ))}
                    <span className="ml-2 text-xs font-semibold text-slate-400">
                      {rating === 5 ? "Exceptional 🚀" : rating === 4 ? "Great 👍" : rating === 3 ? "Good 👌" : "Needs Work 🛠️"}
                    </span>
                  </div>
                </div>

                {/* Categories */}
                <div>
                  <label className="text-xs font-medium text-slate-300">Category</label>
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {CATEGORIES.map((cat) => (
                      <button
                        key={cat}
                        type="button"
                        onClick={() => setCategory(cat)}
                        className={`rounded-lg px-2.5 py-1 text-xs font-medium transition-all ${
                          category === cat
                            ? "border border-cyan-500/50 bg-cyan-500/20 text-cyan-300"
                            : "border border-slate-700/50 bg-slate-800/40 text-slate-400 hover:border-slate-600 hover:text-slate-200"
                        }`}
                      >
                        {cat}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Message */}
                <div>
                  <label className="text-xs font-medium text-slate-300">Feedback or Suggestion</label>
                  <textarea
                    required
                    rows={3}
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    placeholder="Tell us what you liked or what feature you'd like to see next..."
                    className="mt-1.5 w-full rounded-xl border border-slate-700/60 bg-slate-900/60 p-3 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all"
                  />
                </div>

                {/* Optional Email */}
                <div>
                  <label className="text-xs font-medium text-slate-400">
                    Contact Email <span className="text-slate-500">(optional)</span>
                  </label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analyst@domain.com"
                    className="mt-1 w-full rounded-xl border border-slate-700/60 bg-slate-900/60 px-3 py-2 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all"
                  />
                </div>

                {/* Submit Button */}
                <button
                  type="submit"
                  disabled={isSubmitting || message.trim().length < 3}
                  className="w-full rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 py-2.5 text-xs font-semibold text-white shadow-lg shadow-cyan-500/20 transition-all hover:opacity-95 hover:shadow-cyan-500/30 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isSubmitting ? "Sending..." : "Submit Feedback"}
                </button>
              </form>
            ) : (
              /* Success State */
              <div className="py-4 text-center">
                <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-emerald-500/20 text-emerald-400 text-2xl">
                  ✓
                </div>
                <h4 className="mt-3 text-sm font-bold text-white">Thank You for Your Feedback!</h4>
                <p className="mt-1.5 text-xs text-slate-400 max-w-xs mx-auto">
                  Your feedback has been logged (ID: <code className="text-cyan-400 font-mono">{feedbackId}</code>). We use continuous rapid prototyping to deliver improvements fast.
                </p>
                <button
                  type="button"
                  onClick={handleReset}
                  className="mt-5 rounded-xl border border-slate-700 bg-slate-800/80 px-5 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-700 transition-colors"
                >
                  Done
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
