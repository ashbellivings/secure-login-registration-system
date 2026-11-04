import { connectDB, disconnectDB } from '../config/database.ts';
import { executeSecurityTests } from './testRunner.ts';

async function main() {
  console.log('====================================================');
  console.log(' SECURE AUTHENTICATION SYSTEM: AUTOMATED TEST SUITE ');
  console.log(' Cybersecurity Internship Verification Harness      ');
  console.log('====================================================\n');

  try {
    await connectDB();
    console.log('[Test Harness] Database connection established.\n');

    const summary = await executeSecurityTests();

    console.log(`Executed: ${summary.totalTests} tests`);
    console.log(`Passed:   ${summary.passedTests} tests`);
    console.log(`Failed:   ${summary.failedTests} tests\n`);

    console.log('----------------------------------------------------');
    summary.results.forEach((test, idx) => {
      const statusIcon = test.passed ? '✅ PASS' : '❌ FAIL';
      console.log(`${idx + 1}. [${test.category}] ${test.name}`);
      console.log(`   Status: ${statusIcon} | Control: ${test.controlTested}`);
      console.log(`   Evidence: ${test.evidence}\n`);
    });
    console.log('----------------------------------------------------');

    await disconnectDB();

    if (summary.failedTests > 0) {
      console.error(`\nTest suite completed with ${summary.failedTests} failure(s).`);
      process.exit(1);
    } else {
      console.log('\nAll security tests PASSED successfully!');
      process.exit(0);
    }
  } catch (err: any) {
    console.error('Fatal test execution error:', err);
    await disconnectDB();
    process.exit(1);
  }
}

main();
