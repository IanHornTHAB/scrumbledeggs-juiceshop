const fs = require('fs');
const path = require('path');

const REPORTS_DIR = process.env.REPORTS_DIR || 'reports';
const OUTPUT_FILE = path.join(REPORTS_DIR, 'scan-results-local.json');
const PIPELINE_ID = process.env.CI_PIPELINE_ID || 'local-run';
const TIMESTAMP = new Date().toISOString();

function createErrorEntry(toolName, scanType, errorMessage) {
  return {
    tool_name: toolName,
    scan_type: scanType,
    vulnerability_name: 'N/A',
    severity: 'N/A',
    affected_component: 'N/A',
    pipeline_run_id: PIPELINE_ID,
    timestamp: TIMESTAMP,
    status: 'error',
    error_message: errorMessage
  };
}

function parseZapReport() {
  const zapReportPath = path.join(REPORTS_DIR, 'zap-report.html');
  
  if (!fs.existsSync(zapReportPath)) {
    console.warn('WARNING: ZAP report not found at', zapReportPath);
    return [createErrorEntry('ZAP', 'DAST', 'Report file not found')];
  }

  try {
    const htmlContent = fs.readFileSync(zapReportPath, 'utf8');
    const findings = [];
    
    // ZAP HTML Reports enthalten Alerts in einem erkennbaren Muster
    const alertPattern = /<td><a name="[^"]*"><\/a>([^<]+)<\/td>/g;
    const riskPattern = /Risk=([^&\s]+)/g;
    
    let alertMatch;
    let riskMatch;
    const alerts = [];
    const risks = [];
    
    while ((alertMatch = alertPattern.exec(htmlContent)) !== null) {
      alerts.push(alertMatch[1].trim());
    }
    
    while ((riskMatch = riskPattern.exec(htmlContent)) !== null) {
      risks.push(riskMatch[1].trim());
    }
    
    if (alerts.length === 0) {
      console.log('INFO: ZAP report parsed but no alerts found');
      return [{
        tool_name: 'ZAP',
        scan_type: 'DAST',
        vulnerability_name: 'No findings',
        severity: 'INFO',
        affected_component: 'juice-shop',
        pipeline_run_id: PIPELINE_ID,
        timestamp: TIMESTAMP,
        status: 'success'
      }];
    }
    
    alerts.forEach((alert, index) => {
      findings.push({
        tool_name: 'ZAP',
        scan_type: 'DAST',
        vulnerability_name: alert,
        severity: risks[index] || 'Unknown',
        affected_component: 'juice-shop',
        pipeline_run_id: PIPELINE_ID,
        timestamp: TIMESTAMP,
        status: 'success'
      });
    });
    
    return findings;
    
  } catch (error) {
    console.error('ERROR: Failed to parse ZAP report:', error.message);
    return [createErrorEntry('ZAP', 'DAST', error.message)];
  }
}

function collectResults() {
  console.log('Starting result collection for pipeline:', PIPELINE_ID);
  
  // Reports-Ordner anlegen falls nicht vorhanden
  if (!fs.existsSync(REPORTS_DIR)) {
    fs.mkdirSync(REPORTS_DIR, { recursive: true });
  }
  
  // Ergebnisse aller Tools sammeln
  const allFindings = [];
  
  const zapFindings = parseZapReport();
  allFindings.push(...zapFindings);
  
  // Ausgabe-Objekt bauen
  const output = {
    pipeline_run_id: PIPELINE_ID,
    timestamp: TIMESTAMP,
    source: 'juice-shop-pipeline',
    total_findings: allFindings.length,
    findings: allFindings
  };
  
  // JSON-Datei schreiben
  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(output, null, 2), 'utf8');
  
  console.log('SUCCESS: Results written to', OUTPUT_FILE);
  console.log('Total findings:', allFindings.length);
}

// Skript starten
collectResults();