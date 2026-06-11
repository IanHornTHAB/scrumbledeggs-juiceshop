const fs = require('fs');
const path = require('path');

const REPORTS_DIR = process.env.REPORTS_DIR || 'reports';
const OUTPUT_FILE = path.join(REPORTS_DIR, 'scan-results.json');
const PIPELINE_ID = process.env.CI_PIPELINE_ID || 'local-run';
const TIMESTAMP = new Date().toISOString();

function createErrorEntry(toolName, scanType, errorMessage, artifactPath) {
  return {
    tool_name: toolName,
    scan_type: scanType,
    artifact_path: artifactPath || 'N/A',
    vulnerability_name: 'N/A',
    severity: 'N/A',
    affected_component: 'N/A',
    pipeline_run_id: PIPELINE_ID,
    timestamp: TIMESTAMP,
    status: 'error',
    error_message: errorMessage
  };
}

function createNoFindingsEntry(toolName, scanType, artifactPath, affectedComponent) {
  return {
    tool_name: toolName,
    scan_type: scanType,
    artifact_path: artifactPath,
    vulnerability_name: 'No findings',
    severity: 'INFO',
    affected_component: affectedComponent || 'juice-shop',
    pipeline_run_id: PIPELINE_ID,
    timestamp: TIMESTAMP,
    status: 'success'
  };
}

function normalizeSeverity(value) {
  if (value === null || value === undefined || value === '') {
    return 'UNKNOWN';
  }

  const normalized = String(value).trim().toUpperCase();

  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'].includes(normalized)) {
    return normalized;
  }

  if (normalized.includes('CRITICAL') || normalized === '4') {
    return 'CRITICAL';
  }

  if (normalized.includes('HIGH') || normalized === '3' || normalized.includes('ERROR')) {
    return 'HIGH';
  }

  if (normalized.includes('MEDIUM') || normalized === '2' || normalized.includes('WARN')) {
    return 'MEDIUM';
  }

  if (normalized.includes('LOW') || normalized === '1') {
    return 'LOW';
  }

  if (normalized.includes('INFO') || normalized === '0') {
    return 'INFO';
  }

  return normalized;
}

function normalizeZapSeverity(value) {
  if (value === null || value === undefined || value === '') {
    return 'UNKNOWN';
  }

  const normalized = String(value).trim().toUpperCase();

  if (normalized.includes('CRITICAL') || normalized === '4') {
    return 'CRITICAL';
  }

  if (normalized.includes('HIGH') || normalized === '3') {
    return 'HIGH';
  }

  if (normalized.includes('MEDIUM') || normalized === '2') {
    return 'MEDIUM';
  }

  if (normalized.includes('LOW') || normalized === '1') {
    return 'LOW';
  }

  if (normalized.includes('INFO') || normalized === '0') {
    return 'INFO';
  }

  return normalizeSeverity(normalized);
}

function readJsonReport(filePath) {
  if (!fs.existsSync(filePath)) {
    return {
      ok: false,
      errorMessage: 'Report file not found'
    };
  }

  try {
    return {
      ok: true,
      data: JSON.parse(fs.readFileSync(filePath, 'utf8'))
    };
  } catch (error) {
    return {
      ok: false,
      errorMessage: error.message
    };
  }
}

function readHtmlReport(filePath) {
  if (!fs.existsSync(filePath)) {
    return {
      ok: false,
      errorMessage: 'Report file not found'
    };
  }

  try {
    return {
      ok: true,
      data: fs.readFileSync(filePath, 'utf8')
    };
  } catch (error) {
    return {
      ok: false,
      errorMessage: error.message
    };
  }
}

function buildArtifactRecord(toolName, scanType, artifactPath, status, resultCount, report, errorMessage) {
  const artifact = {
    tool_name: toolName,
    scan_type: scanType,
    artifact_path: artifactPath,
    status,
    result_count: resultCount,
    report
  };

  if (errorMessage) {
    artifact.error_message = errorMessage;
  }

  return artifact;
}

function parseSemgrepReport() {
  const artifactPath = 'semgrep-report.json';
  const reportPath = path.join(REPORTS_DIR, artifactPath);
  const report = readJsonReport(reportPath);

  if (!report.ok) {
    return {
      findings: [createErrorEntry('Semgrep', 'SAST', report.errorMessage, artifactPath)],
      artifact: buildArtifactRecord('Semgrep', 'SAST', artifactPath, 'error', 0, null, report.errorMessage)
    };
  }

  const results = Array.isArray(report.data.results) ? report.data.results : [];

  if (results.length === 0) {
    return {
      findings: [createNoFindingsEntry('Semgrep', 'SAST', artifactPath, 'app')],
      artifact: buildArtifactRecord('Semgrep', 'SAST', artifactPath, 'success', 0, report.data)
    };
  }

  const findings = results.map(result => ({
    tool_name: 'Semgrep',
    scan_type: 'SAST',
    artifact_path: artifactPath,
    vulnerability_name: result.check_id || result.extra?.message || 'Semgrep finding',
    severity: normalizeSeverity(result.extra?.severity || result.extra?.metadata?.severity),
    affected_component: result.path || 'app',
    pipeline_run_id: PIPELINE_ID,
    timestamp: TIMESTAMP,
    status: 'success',
    details: {
      message: result.extra?.message,
      rule_id: result.check_id,
      path: result.path,
      start_line: result.start?.line,
      end_line: result.end?.line
    }
  }));

  return {
    findings,
    artifact: buildArtifactRecord('Semgrep', 'SAST', artifactPath, 'success', findings.length, report.data)
  };
}

function parseGitleaksReport() {
  const artifactPath = 'gitleaks-report.json';
  const reportPath = path.join(REPORTS_DIR, artifactPath);
  const report = readJsonReport(reportPath);

  if (!report.ok) {
    return {
      findings: [createErrorEntry('Gitleaks', 'SECRET_DETECTION', report.errorMessage, artifactPath)],
      artifact: buildArtifactRecord('Gitleaks', 'SECRET_DETECTION', artifactPath, 'error', 0, null, report.errorMessage)
    };
  }

  const rawFindingsData = Array.isArray(report.data)
    ? report.data
    : Array.isArray(report.data.findings)
      ? report.data.findings
      : [];

  // Gitleaks scans the full git history, so the same secret is re-reported in
  // every commit it appears in. Collapse those to unique secrets (rule+file+secret)
  // so the dashboard counts real distinct findings instead of per-commit duplicates.
  const seenSecrets = new Set();
  const findingsData = rawFindingsData.filter(result => {
    const dedupeKey = [
      result.RuleID || result.rule_id || '',
      result.File || result.file || '',
      result.Secret || result.secret || result.Match || result.match || ''
    ].join('|');
    if (seenSecrets.has(dedupeKey)) return false;
    seenSecrets.add(dedupeKey);
    return true;
  });

  if (findingsData.length === 0) {
    return {
      findings: [createNoFindingsEntry('Gitleaks', 'SECRET_DETECTION', artifactPath, 'repository')],
      artifact: buildArtifactRecord('Gitleaks', 'SECRET_DETECTION', artifactPath, 'success', 0, report.data)
    };
  }

  const findings = findingsData.map(result => ({
    tool_name: 'Gitleaks',
    scan_type: 'SECRET_DETECTION',
    artifact_path: artifactPath,
    vulnerability_name: result.Description || result.description || result.RuleID || result.rule_id || 'Secret detection finding',
    severity: normalizeSeverity(result.Severity || result.severity || 'MEDIUM'),
    affected_component: result.File || result.file || 'repository',
    pipeline_run_id: PIPELINE_ID,
    timestamp: TIMESTAMP,
    status: 'success',
    details: {
      rule_id: result.RuleID || result.rule_id,
      file: result.File || result.file,
      line: result.Line || result.line,
      commit: result.Commit || result.commit,
      match: result.Match || result.match
    }
  }));

  return {
    findings,
    artifact: buildArtifactRecord('Gitleaks', 'SECRET_DETECTION', artifactPath, 'success', findings.length, report.data)
  };
}

function extractZapAlerts(reportData) {
  const findings = [];
  const sites = Array.isArray(reportData.site) ? reportData.site : [];

  sites.forEach(site => {
    const siteName = site['@name'] || site.name || 'juice-shop';
    const alerts = Array.isArray(site.alerts) ? site.alerts : [];

    alerts.forEach(alert => {
      findings.push({
        tool_name: 'ZAP',
        scan_type: 'DAST',
        artifact_path: 'zap-report.json',
        vulnerability_name: alert.alert || alert.name || 'ZAP alert',
        severity: normalizeZapSeverity(alert.riskdesc || alert.riskcode || alert.risk || alert.severity),
        affected_component: siteName,
        pipeline_run_id: PIPELINE_ID,
        timestamp: TIMESTAMP,
        status: 'success',
        details: {
          confidence: alert.confidence,
          cweid: alert.cweid,
          wascid: alert.wascid,
          description: alert.desc,
          solution: alert.solution,
          reference: alert.reference
        }
      });
    });
  });

  return findings;
}

function parseZapReport() {
  const jsonArtifactPath = 'zap-report.json';
  const jsonReportPath = path.join(REPORTS_DIR, jsonArtifactPath);
  const jsonReport = readJsonReport(jsonReportPath);

  if (jsonReport.ok) {
    const findings = extractZapAlerts(jsonReport.data);

    if (findings.length === 0) {
      return {
        findings: [createNoFindingsEntry('ZAP', 'DAST', jsonArtifactPath, 'juice-shop')],
        artifact: buildArtifactRecord('ZAP', 'DAST', jsonArtifactPath, 'success', 0, jsonReport.data)
      };
    }

    return {
      findings,
      artifact: buildArtifactRecord('ZAP', 'DAST', jsonArtifactPath, 'success', findings.length, jsonReport.data)
    };
  }

  const htmlArtifactPath = 'zap-report.html';
  const htmlReportPath = path.join(REPORTS_DIR, htmlArtifactPath);
  const htmlReport = readHtmlReport(htmlReportPath);

  if (!htmlReport.ok) {
    return {
      findings: [createErrorEntry('ZAP', 'DAST', htmlReport.errorMessage, htmlArtifactPath)],
      artifact: buildArtifactRecord('ZAP', 'DAST', htmlArtifactPath, 'error', 0, null, htmlReport.errorMessage)
    };
  }

  try {
    const htmlContent = htmlReport.data;
    const findings = [];
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
      return {
        findings: [createNoFindingsEntry('ZAP', 'DAST', htmlArtifactPath, 'juice-shop')],
        artifact: buildArtifactRecord('ZAP', 'DAST', htmlArtifactPath, 'success', 0, { source: 'html', file: htmlArtifactPath })
      };
    }

    alerts.forEach((alert, index) => {
      findings.push({
        tool_name: 'ZAP',
        scan_type: 'DAST',
        artifact_path: htmlArtifactPath,
        vulnerability_name: alert,
        severity: normalizeZapSeverity(risks[index] || 'UNKNOWN'),
        affected_component: 'juice-shop',
        pipeline_run_id: PIPELINE_ID,
        timestamp: TIMESTAMP,
        status: 'success'
      });
    });

    return {
      findings,
      artifact: buildArtifactRecord('ZAP', 'DAST', htmlArtifactPath, 'success', findings.length, { source: 'html', file: htmlArtifactPath })
    };
  } catch (error) {
    return {
      findings: [createErrorEntry('ZAP', 'DAST', error.message, htmlArtifactPath)],
      artifact: buildArtifactRecord('ZAP', 'DAST', htmlArtifactPath, 'error', 0, { source: 'html', file: htmlArtifactPath }, error.message)
    };
  }
}

function parseFuzzingReport(filePath) {
  const artifactPath = path.relative(REPORTS_DIR, filePath) || path.basename(filePath);
  const report = readJsonReport(filePath);

  if (!report.ok) {
    return {
      findings: [createErrorEntry('ffuf', 'FUZZING', report.errorMessage, artifactPath)],
      artifact: buildArtifactRecord('ffuf', 'FUZZING', artifactPath, 'error', 0, null, report.errorMessage)
    };
  }

  const results = Array.isArray(report.data.results) ? report.data.results : [];

  if (results.length === 0) {
    return {
      findings: [createNoFindingsEntry('ffuf', 'FUZZING', artifactPath, 'endpoint')],
      artifact: buildArtifactRecord('ffuf', 'FUZZING', artifactPath, 'success', 0, report.data)
    };
  }

  const findings = results.map(result => {
    const status = Number(result.status);
    let severity = 'INFO';

    if (Number.isFinite(status) && status >= 500) {
      severity = 'HIGH';
    } else if (Number.isFinite(status) && status >= 400) {
      severity = 'MEDIUM';
    }

    const target = result.url || result.input || 'fuzzing target';

    return {
      tool_name: 'ffuf',
      scan_type: 'FUZZING',
      artifact_path: artifactPath,
      vulnerability_name: `Fuzzing hit: ${target}`,
      severity,
      affected_component: target,
      pipeline_run_id: PIPELINE_ID,
      timestamp: TIMESTAMP,
      status: 'success',
      details: {
        status: result.status,
        input: result.input,
        length: result.length,
        words: result.words,
        lines: result.lines,
        redirectlocation: result.redirectlocation,
        duration: result.duration
      }
    };
  });

  return {
    findings,
    artifact: buildArtifactRecord('ffuf', 'FUZZING', artifactPath, 'success', findings.length, report.data)
  };
}

function collectFuzzingReports() {
  const fuzzingDir = path.join(REPORTS_DIR, 'fuzzing');

  if (!fs.existsSync(fuzzingDir)) {
    return {
      findings: [createErrorEntry('ffuf', 'FUZZING', 'Fuzzing report directory not found', 'fuzzing/')],
      artifacts: [buildArtifactRecord('ffuf', 'FUZZING', 'fuzzing/', 'error', 0, null, 'Fuzzing report directory not found')]
    };
  }

  const reportFiles = fs
    .readdirSync(fuzzingDir)
    .filter(fileName => fileName.toLowerCase().endsWith('.json'))
    .sort((left, right) => left.localeCompare(right));

  if (reportFiles.length === 0) {
    return {
      findings: [createNoFindingsEntry('ffuf', 'FUZZING', 'fuzzing/', 'endpoint')],
      artifacts: [buildArtifactRecord('ffuf', 'FUZZING', 'fuzzing/', 'success', 0, { reports: [] })]
    };
  }

  const findings = [];
  const artifacts = [];

  reportFiles.forEach(fileName => {
    const result = parseFuzzingReport(path.join(fuzzingDir, fileName));
    findings.push(...result.findings);
    artifacts.push(result.artifact);
  });

  return {
    findings,
    artifacts
  };
}

function collectResults() {
  console.log('Starting result collection for pipeline:', PIPELINE_ID);

  if (!fs.existsSync(REPORTS_DIR)) {
    fs.mkdirSync(REPORTS_DIR, { recursive: true });
  }

  const semgrepResult = parseSemgrepReport();
  const gitleaksResult = parseGitleaksReport();
  const zapResult = parseZapReport();
  const fuzzingResult = collectFuzzingReports();

  const allFindings = [
    ...semgrepResult.findings,
    ...gitleaksResult.findings,
    ...zapResult.findings,
    ...fuzzingResult.findings
  ];

  const countRealFindings = findings =>
    findings.filter(f => f.status === 'success' && f.vulnerability_name !== 'No findings').length;

  const output = {
    pipeline_run_id: PIPELINE_ID,
    timestamp: TIMESTAMP,
    source: 'juice-shop-pipeline',
    total_findings: countRealFindings(allFindings),
    stage_summary: {
      sast: countRealFindings(semgrepResult.findings),
      secret_detection: countRealFindings(gitleaksResult.findings),
      dast: countRealFindings(zapResult.findings),
      fuzzing: countRealFindings(fuzzingResult.findings)
    },
    artifacts: {
      sast: {
        semgrep: semgrepResult.artifact
      },
      secret_detection: {
        gitleaks: gitleaksResult.artifact
      },
      dast: {
        zap: zapResult.artifact
      },
      fuzzing: fuzzingResult.artifacts
    },
    findings: allFindings
  };

  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(output, null, 2), 'utf8');

  console.log('SUCCESS: Results written to', OUTPUT_FILE);
  console.log('Total findings:', allFindings.length);
}

collectResults();