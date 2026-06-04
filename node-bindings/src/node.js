import { fileURLToPath } from 'node:url'
import { dlopen } from 'node:process'

const module = { exports: {} }
dlopen(module, fileURLToPath(new URL('../hivemind.node', import.meta.url)), 2)

export const HivemindServer = module.exports