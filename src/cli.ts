#!/usr/bin/env node
import { Command } from 'commander';
import { initCommand } from './commands/init.js';
import { keygenCommand } from './commands/keygen.js';
import { signCommand } from './commands/sign.js';
import { verifyCommand } from './commands/verify.js';
import { doctorCommand } from './commands/doctor.js';

const program = new Command();

program
  .name('llmo')
  .description('Reference CLI for the LLMO protocol. Sign and verify llmo.json documents per https://llmo.org/spec/v0.1')
  .version('0.1.0');

program.addCommand(initCommand());
program.addCommand(keygenCommand());
program.addCommand(signCommand());
program.addCommand(verifyCommand());
program.addCommand(doctorCommand());

await program.parseAsync(process.argv);
