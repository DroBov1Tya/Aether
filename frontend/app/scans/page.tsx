import { Suspense } from "react";
import ScanForm from "./scan-form";

export default function ScansPage() {
  return (
    <div className="page-container">
      <h1 className="page-title">SCAN MANAGER</h1>
      <p style={{ color: "#818b98", marginBottom: 32 }}>
        Configure and launch network reconnaissance scans
      </p>

      <Suspense
        fallback={
          <div style={{ textAlign: "center", padding: 40, color: "#818b98" }}>
            Loading scan interface...
          </div>
        }
      >
        <ScanForm />
      </Suspense>
    </div>
  );
}
