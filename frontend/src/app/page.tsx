export default function Home() {
  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-7xl px-6 py-8">
        <header className="flex items-center justify-between border-b border-slate-800 pb-6">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">
              SentinelFlow
            </h1>

            <p className="mt-1 text-sm text-slate-400">
              Passive AI Threat Intelligence
            </p>
          </div>

          <div className="flex items-center gap-4 text-sm">
            <span className="flex items-center gap-2 text-emerald-400">
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
              Sensor Online
            </span>

            <span className="rounded-md border border-slate-700 px-3 py-1.5 text-slate-300">
              READ-ONLY
            </span>
          </div>
        </header>

        <section className="grid gap-4 py-6 md:grid-cols-4">
          <Metric title="Flows/sec" value="0" />
          <Metric title="Threats" value="0" />
          <Metric title="Critical" value="0" />
          <Metric title="Detection Latency" value="—" />
        </section>

        <section className="grid gap-6 lg:grid-cols-3">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-6 lg:col-span-2">
            <h2 className="text-sm font-medium text-slate-300">
              Traffic Activity
            </h2>

            <div className="flex h-80 items-center justify-center text-sm text-slate-500">
              Waiting for passive telemetry...
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
            <h2 className="text-sm font-medium text-slate-300">
              Threat Distribution
            </h2>

            <div className="mt-6 space-y-4 text-sm text-slate-500">
              <p>No detections yet.</p>
            </div>
          </div>
        </section>

        <section className="mt-6 rounded-xl border border-slate-800 bg-slate-900 p-6">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-medium text-slate-300">
              Live Intelligence
            </h2>

            <span className="text-xs text-slate-500">
              ALERT ONLY
            </span>
          </div>

          <div className="mt-6 rounded-lg border border-dashed border-slate-800 p-10 text-center text-sm text-slate-500">
            No alerts received.
          </div>
        </section>
      </div>
    </main>
  );
}

function Metric({
  title,
  value,
}: {
  title: string;
  value: string;
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
      <p className="text-xs uppercase tracking-wider text-slate-500">
        {title}
      </p>

      <p className="mt-2 text-2xl font-semibold">{value}</p>
    </div>
  );
}
