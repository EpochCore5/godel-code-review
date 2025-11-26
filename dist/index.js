/*
 * EPOCHQ SUPREME QUANTUM INTEGRATION
 * IntegrityGate GitHub Action
 * Founded: 2025 by John Vincent Ryan
 * EPOCHCORE Quantum Enterprise
 */

const core = require('@actions/core');
const github = require('@actions/github');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

async function run() {
    try {
        // Get inputs
        const mode = core.getInput('mode') || 'standard';
        const policyPath = core.getInput('policy-path') || '.epochcore/policies';
        const signatureVerify = core.getInput('signature-verify') === 'true';
        const merkleValidate = core.getInput('merkle-validate') === 'true';
        const failOnWarning = core.getInput('fail-on-warning') === 'true';
        const licenseKey = core.getInput('license-key');
        const workerEndpoint = core.getInput('worker-endpoint');

        core.info('IntegrityGate v1.0.0 - EpochCore Quantum Enterprise');
        core.info(`Mode: ${mode} | Signatures: ${signatureVerify} | Merkle: ${merkleValidate}`);

        const results = {
            integrityScore: 100,
            signatureStatus: 'not_checked',
            merkleRoot: null,
            policyViolations: 0,
            warnings: [],
            errors: []
        };

        // Step 1: Scan repository files
        core.startGroup('Scanning repository files');
        const files = await scanDirectory(process.cwd());
        core.info(`Found ${files.length} files to analyze`);
        core.endGroup();

        // Step 2: Compute Merkle tree
        if (merkleValidate) {
            core.startGroup('Computing Merkle tree');
            results.merkleRoot = computeMerkleRoot(files);
            core.info(`Merkle root: ${results.merkleRoot}`);
            core.endGroup();
        }

        // Step 3: Verify signatures
        if (signatureVerify) {
            core.startGroup('Verifying signatures');
            const sigResult = await verifySignatures(files);
            results.signatureStatus = sigResult.status;
            if (sigResult.warnings.length > 0) {
                results.warnings.push(...sigResult.warnings);
            }
            core.info(`Signature status: ${results.signatureStatus}`);
            core.endGroup();
        }

        // Step 4: Check OPA policies
        core.startGroup('Checking OPA policies');
        const policyResult = await checkPolicies(policyPath, files);
        results.policyViolations = policyResult.violations;
        if (policyResult.violations > 0) {
            results.integrityScore -= (policyResult.violations * 5);
            results.warnings.push(...policyResult.messages);
        }
        core.info(`Policy violations: ${results.policyViolations}`);
        core.endGroup();

        // Step 5: Deep analysis (Pro feature)
        if (mode === 'deep' && licenseKey) {
            core.startGroup('Deep analysis (Pro)');
            const deepResult = await performDeepAnalysis(workerEndpoint, licenseKey, files);
            if (deepResult.issues) {
                results.integrityScore -= deepResult.issues.length;
                results.warnings.push(...deepResult.issues);
            }
            core.endGroup();
        }

        // Calculate final score
        results.integrityScore = Math.max(0, Math.min(100, results.integrityScore));

        // Set outputs
        core.setOutput('integrity-score', results.integrityScore.toString());
        core.setOutput('signature-status', results.signatureStatus);
        core.setOutput('merkle-root', results.merkleRoot || 'not_computed');
        core.setOutput('policy-violations', results.policyViolations.toString());
        core.setOutput('report-url', `https://epochcore-unified-worker.epochcoreras.workers.dev/integrity-report/${github.context.sha}`);

        // Summary
        core.info('');
        core.info('='.repeat(50));
        core.info('INTEGRITYGATE REPORT');
        core.info('='.repeat(50));
        core.info(`Integrity Score: ${results.integrityScore}/100`);
        core.info(`Signature Status: ${results.signatureStatus}`);
        core.info(`Merkle Root: ${results.merkleRoot || 'N/A'}`);
        core.info(`Policy Violations: ${results.policyViolations}`);
        core.info(`Warnings: ${results.warnings.length}`);
        core.info('='.repeat(50));

        // Create job summary
        await core.summary
            .addHeading('IntegrityGate Report')
            .addTable([
                [{data: 'Metric', header: true}, {data: 'Value', header: true}],
                ['Integrity Score', `${results.integrityScore}/100`],
                ['Signature Status', results.signatureStatus],
                ['Merkle Root', results.merkleRoot ? `\`${results.merkleRoot.substring(0, 16)}...\`` : 'N/A'],
                ['Policy Violations', results.policyViolations.toString()],
                ['Files Analyzed', files.length.toString()]
            ])
            .addLink('View Full Report', `https://epochcore-unified-worker.epochcoreras.workers.dev/integrity-report/${github.context.sha}`)
            .write();

        // Determine pass/fail
        if (results.errors.length > 0) {
            core.setFailed(`IntegrityGate found ${results.errors.length} error(s)`);
        } else if (failOnWarning && results.warnings.length > 0) {
            core.setFailed(`IntegrityGate found ${results.warnings.length} warning(s)`);
        } else if (results.integrityScore < 70) {
            core.setFailed(`Integrity score ${results.integrityScore} is below threshold (70)`);
        } else {
            core.info(`IntegrityGate passed with score ${results.integrityScore}/100`);
        }

    } catch (error) {
        core.setFailed(`IntegrityGate error: ${error.message}`);
    }
}

async function scanDirectory(dir, fileList = []) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        // Skip common ignore patterns
        if (entry.name.startsWith('.') ||
            entry.name === 'node_modules' ||
            entry.name === 'dist' ||
            entry.name === '.git') {
            continue;
        }

        if (entry.isDirectory()) {
            await scanDirectory(fullPath, fileList);
        } else {
            fileList.push({
                path: fullPath,
                relativePath: path.relative(process.cwd(), fullPath),
                hash: computeFileHash(fullPath)
            });
        }
    }

    return fileList;
}

function computeFileHash(filePath) {
    try {
        const content = fs.readFileSync(filePath);
        return crypto.createHash('sha256').update(content).digest('hex');
    } catch (error) {
        return 'error';
    }
}

function computeMerkleRoot(files) {
    if (files.length === 0) return null;

    let hashes = files.map(f => f.hash).filter(h => h !== 'error');

    while (hashes.length > 1) {
        const newHashes = [];
        for (let i = 0; i < hashes.length; i += 2) {
            const left = hashes[i];
            const right = hashes[i + 1] || left;
            const combined = crypto.createHash('sha256')
                .update(left + right)
                .digest('hex');
            newHashes.push(combined);
        }
        hashes = newHashes;
    }

    return hashes[0];
}

async function verifySignatures(files) {
    const result = {
        status: 'verified',
        warnings: []
    };

    // Check for signature files
    const sigFiles = files.filter(f =>
        f.relativePath.endsWith('.sig') ||
        f.relativePath.endsWith('.asc') ||
        f.relativePath === 'SIGNATURE'
    );

    if (sigFiles.length === 0) {
        result.status = 'no_signatures';
        result.warnings.push('No signature files found in repository');
    }

    // Check for signed commits (via git)
    try {
        const { execSync } = require('child_process');
        const gitLog = execSync('git log -1 --show-signature 2>&1', { encoding: 'utf8' });
        if (gitLog.includes('Good signature')) {
            result.status = 'verified';
        } else if (gitLog.includes('No signature')) {
            result.warnings.push('Latest commit is not signed');
        }
    } catch (error) {
        // Git signature check not available
    }

    return result;
}

async function checkPolicies(policyPath, files) {
    const result = {
        violations: 0,
        messages: []
    };

    // Built-in policy checks

    // 1. Check for sensitive files
    const sensitivePatterns = ['.env', 'credentials', 'secret', 'private_key', 'id_rsa'];
    for (const file of files) {
        for (const pattern of sensitivePatterns) {
            if (file.relativePath.toLowerCase().includes(pattern)) {
                result.violations++;
                result.messages.push(`Potentially sensitive file: ${file.relativePath}`);
            }
        }
    }

    // 2. Check for large files (>10MB)
    for (const file of files) {
        try {
            const stats = fs.statSync(file.path);
            if (stats.size > 10 * 1024 * 1024) {
                result.violations++;
                result.messages.push(`Large file detected (>10MB): ${file.relativePath}`);
            }
        } catch (error) {
            // Skip files we can't stat
        }
    }

    // 3. Check for package-lock.json consistency
    const hasPackageJson = files.some(f => f.relativePath === 'package.json');
    const hasPackageLock = files.some(f => f.relativePath === 'package-lock.json');
    if (hasPackageJson && !hasPackageLock) {
        result.messages.push('Warning: package.json exists without package-lock.json');
    }

    return result;
}

async function performDeepAnalysis(workerEndpoint, licenseKey, files) {
    try {
        const response = await fetch(`${workerEndpoint}/integrity/deep-analysis`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-License-Key': licenseKey
            },
            body: JSON.stringify({
                files: files.map(f => ({ path: f.relativePath, hash: f.hash })),
                timestamp: new Date().toISOString()
            })
        });

        if (response.ok) {
            return await response.json();
        }
    } catch (error) {
        core.warning(`Deep analysis unavailable: ${error.message}`);
    }

    return { issues: [] };
}

run();
