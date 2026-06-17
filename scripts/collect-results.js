const fs = require('fs');
const path = require('path');

const reportsDir = process.env.REPORTS_DIR || 'reports';
const outputFile = path.join(reportsDir, 'scan-results.json');

function loadJson(filePath) {
    try {
        if (fs.existsSync(filePath)) {
            return JSON.parse(fs.readFileSync(filePath, 'utf8'));
        }
    } catch (error) {
        console.error(`Fehler beim Lesen von ${filePath}:`, error.message);
    }
    return null;
}

console.log('Sammle alle Testergebnisse inklusive Fuzzing... 🚀');

const results = {
    summary: {
        total_vulnerabilities: 0,
        semgrep_findings: 0,
        gitleaks_findings: 0,
        trivy_findings: 0,
        fuzzing_findings: 0
    },
    scans: {
        semgrep: [],
        gitleaks: [],
        trivy: [],
        fuzzing: []
    }
};

const semgrepData = loadJson('semgrep-report.json');
if (semgrepData && semgrepData.results) {
    results.scans.semgrep = semgrepData.results.map(f => ({
        id: f.check_id,
        path: f.path,
        line: f.start?.line,
        message: f.extra?.message,
        severity: f.extra?.severity
    }));
    results.summary.semgrep_findings = results.scans.semgrep.length;
}

const gitleaksData = loadJson('gitleaks-report.json');
if (gitleaksData && Array.isArray(gitleaksData)) {
    results.scans.gitleaks = gitleaksData.map(f => ({
        description: f.Description,
        file: f.File,
        line: f.StartLine,
        secret: f.Secret ? `${f.Secret.substring(0, 4)}... [REDACTED]` : 'Unknown',
        rule: f.RuleID
    }));
    results.summary.gitleaks_findings = results.scans.gitleaks.length;
}

const trivyData = loadJson('reports/trivy-report.json');
if (trivyData && trivyData.Results) {
    const vulns = [];
    trivyData.Results.forEach(res => {
        if (res.Vulnerabilities) {
            res.Vulnerabilities.forEach(v => {
                vulns.push({
                    id: v.VulnerabilityID,
                    pkg: v.PkgName,
                    installed_version: v.InstalledVersion,
                    fixed_version: v.FixedVersion,
                    severity: v.Severity,
                    title: v.Title
                });
            });
        }
    });
    results.scans.trivy = vulns;
    results.summary.trivy_findings = vulns.length;
}

const fuzzFiles = ['endpoints.json', 'login-fuzz.json', 'search-fuzz.json'];
const fuzzFindings = [];

fuzzFiles.forEach(file => {
    const filePath = path.join(reportsDir, 'fuzzing', file);
    const fuzzData = loadJson(filePath);
    
    if (fuzzData && fuzzData.results) {
        fuzzData.results.forEach(r => {
            if (r.status === 500 || r.status === 200) { 
                fuzzFindings.push({
                    scanner: 'ffuf',
                    source_file: file,
                    url: r.url,
                    method: r.method,
                    input: r.input, 
                    status: r.status,
                    length: r.length,
                    words: r.words
                });
            }
        });
    }
});

results.scans.fuzzing = fuzzFindings;
results.summary.fuzzing_findings = fuzzFindings.length;

// Gesamtzahl berechnen
results.summary.total_vulnerabilities = 
    results.summary.semgrep_findings + 
    results.summary.gitleaks_findings + 
    results.summary.trivy_findings +
    results.summary.fuzzing_findings;

// Ergebnisse ordnungsgemäß wegschreiben
if (!fs.existsSync(reportsDir)){
    fs.mkdirSync(reportsDir, { recursive: true });
}

fs.writeFileSync(outputFile, JSON.stringify(results, null, 2));
console.log(`Ergebnisse erfolgreich in ${outputFile} gespeichert! ✅`);
console.log(`Fuzzing Findings: ${results.summary.fuzzing_findings}`);
console.log(`Gesamte Findings für das Dashboard: ${results.summary.total_vulnerabilities}`);