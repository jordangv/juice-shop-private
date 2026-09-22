/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { challenges } from '../../data/datacache'
import { type Challenge } from '@juice-shop/data/types'
import { checkUploadSize, checkFileType, handleYamlUpload } from '../../routes/fileUpload'

void describe('fileUpload', () => {
  let req: any
  let res: any
  let save: any

  beforeEach(() => {
    req = { file: { originalname: '' } }
    res = {}
    save = () => ({
      then () { }
    })
  })

  void describe('should not solve "uploadSizeChallenge" when file size is', () => {
    const sizes = [0, 1, 100, 1000, 10000, 99999, 100000]
    sizes.forEach(size => {
      void it(`${size} bytes`, () => {
        challenges.uploadSizeChallenge = { solved: false, save } as unknown as Challenge
        req.file.size = size

        checkUploadSize(req, res, () => {})

        assert.equal(challenges.uploadSizeChallenge.solved, false)
      })
    })
  })

  void it('should solve "uploadSizeChallenge" when file size exceeds 100000 bytes', () => {
    challenges.uploadSizeChallenge = { solved: false, save } as unknown as Challenge
    req.file.size = 100001

    checkUploadSize(req, res, () => {})

    assert.equal(challenges.uploadSizeChallenge.solved, true)
  })

  void it('should solve "uploadTypeChallenge" when file type is not PDF', () => {
    challenges.uploadTypeChallenge = { solved: false, save } as unknown as Challenge
    req.file.originalname = 'hack.exe'

    checkFileType(req, res, () => {})

    assert.equal(challenges.uploadTypeChallenge.solved, true)
  })

  void it('should not solve "uploadTypeChallenge" when file type is PDF', () => {
    challenges.uploadTypeChallenge = { solved: false, save } as unknown as Challenge
    req.file.originalname = 'hack.pdf'

    checkFileType(req, res, () => {})

    assert.equal(challenges.uploadTypeChallenge.solved, false)
  })

  void describe('handleYamlUpload', () => {
    let statusCodes: number[]
    let yamlRes: any
    let nextArgs: any[]

    beforeEach(() => {
      challenges.deprecatedInterfaceChallenge = { solved: false, save } as unknown as Challenge
      challenges.yamlBombChallenge = { solved: false, save } as unknown as Challenge
      statusCodes = []
      nextArgs = []
      yamlRes = {
        status (code: number) {
          statusCodes.push(code)
          return yamlRes
        },
        end () {}
      }
    })

    void it('should reject YAML with a "!!js/function" tag without executing its code', () => {
      const marker = '__juiceShopYamlUploadRce'
      delete (globalThis as any)[marker]
      const payload = `toJSON: !!js/function "function () { globalThis.${marker} = true; return 1 }"\n`
      const yamlReq = { file: { originalname: 'rce.yml', buffer: Buffer.from(payload) } } as any

      handleYamlUpload(yamlReq, yamlRes, (err?: any) => { nextArgs.push(err) })

      assert.equal((globalThis as any)[marker], undefined)
      assert.ok(nextArgs[0] instanceof Error)
      assert.match(nextArgs[0].message, /unknown tag/)
      assert.ok(statusCodes.includes(410))
    })

    void it('should still deserialize harmless YAML into the deprecation message', () => {
      const yamlReq = { file: { originalname: 'complaint.yml', buffer: Buffer.from('a: 1\nb:\n  - x\n') } } as any

      handleYamlUpload(yamlReq, yamlRes, (err?: any) => { nextArgs.push(err) })

      assert.ok(nextArgs[0] instanceof Error)
      assert.match(nextArgs[0].message, /\{"a":1,"b":\["x"\]\}/)
      assert.ok(statusCodes.includes(410))
    })
  })
})
