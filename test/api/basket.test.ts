/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import fs from 'node:fs'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { QuantityModel } from '../../models/quantity'
import { WalletModel } from '../../models/wallet'
import * as db from '../../data/mongodb'
import * as security from '../../lib/insecurity'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }

const validCoupon = security.generateCoupon(15)
const outdatedCoupon = security.generateCoupon(20, new Date(2001, 0, 1))
const forgedCoupon = security.generateCoupon(99)

// Records every order confirmation file stream opened by this test process, together with the bytes piped into it.
// Only this process' own streams are inspected, because ftp/ is shared with (and cleaned up by) concurrently running API test files.
function spyOnOrderFileStreams (t: TestContext) {
  const createWriteStream = fs.createWriteStream
  const orderFileStreams: Array<{ file: string, stream: fs.WriteStream, bytes: Buffer[] }> = []
  t.mock.method(fs, 'createWriteStream', (file: fs.PathLike, options?: Parameters<typeof fs.createWriteStream>[1]) => {
    const stream = createWriteStream(file, options)
    if (path.basename(String(file)).startsWith('order_')) {
      const orderFileStream = { file: String(file), stream, bytes: [] as Buffer[] }
      stream.once('pipe', (source) => { source.on('data', (chunk: Buffer) => { orderFileStream.bytes.push(chunk) }) })
      orderFileStreams.push(orderFileStream)
    }
    return stream
  })
  return orderFileStreams
}

before(
  async () => {
    const result = await createTestApp()
    app = result.app

    const { token } = await login(app, {
      email: 'jim@juice-sh.op',
      password: 'ncc-1701'
    })
    authHeader = {
      Authorization: 'Bearer ' + token,
      'content-type': 'application/json'
    }
  },
  { timeout: 60000 }
)

void describe('/rest/basket/:id', () => {
  void it('GET existing basket by id is not allowed via public API', async () => {
    const res = await request(app).get('/rest/basket/1')
    assert.equal(res.status, 401)
  })

  void it('GET empty basket when requesting non-existing basket id', async () => {
    const res = await request(app).get('/rest/basket/4711').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(res.body.data === null || (typeof res.body.data === 'object' && Object.keys(res.body.data).length === 0))
  })

  void it('GET existing basket with contained products by id', async () => {
    const res = await request(app).get('/rest/basket/1').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.id, 1)
    assert.equal(res.body.data.Products.length, 3)
  })

  void it('GET basket should accept forged JWTs', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({ data: { email: 'jim@juice-sh.op' }, iat: 1508639612, exp: 9999999999 })).toString('base64url')
    const unsignedToken = `${header}.${payload}.`
    const res = await request(app)
      .get('/rest/basket/1')
      .set({ Authorization: 'Bearer ' + unsignedToken, 'content-type': 'application/json' })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
  })
})

void describe('/api/Baskets', () => {
  void it('POST new basket is not part of API', async () => {
    const res = await request(app)
      .post('/api/Baskets')
      .set(authHeader)
      .send({ UserId: 1 })
    assert.equal(res.status, 500)
  })

  void it('GET all baskets is not part of API', async () => {
    const res = await request(app).get('/api/Baskets').set(authHeader)
    assert.equal(res.status, 500)
  })
})

void describe('/api/Baskets/:id', () => {
  void it('GET existing basket is not part of API', async () => {
    const res = await request(app).get('/api/Baskets/1').set(authHeader)
    assert.equal(res.status, 500)
  })

  void it('PUT update existing basket is not part of API', async () => {
    const res = await request(app)
      .put('/api/Baskets/1')
      .set(authHeader)
      .send({ UserId: 2 })
    assert.equal(res.status, 500)
  })

  void it('DELETE existing basket is not part of API', async () => {
    const res = await request(app).delete('/api/Baskets/1').set(authHeader)
    assert.equal(res.status, 500)
  })
})

void describe('/rest/basket/:id', () => {
  void it('GET existing basket of another user', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    const res = await request(app)
      .get('/rest/basket/2')
      .set({ Authorization: 'Bearer ' + token })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.id, 2)
  })
})

void describe('/rest/basket/:id/checkout', () => {
  void it('POST placing an order for a basket is not allowed via public API', async () => {
    const res = await request(app).post('/rest/basket/1/checkout')
    assert.equal(res.status, 401)
  })

  void it('POST placing an order for an existing basket returns orderId', async () => {
    const res = await request(app).post('/rest/basket/1/checkout').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.orderConfirmation !== undefined)
  })

  void it('POST placing an order for a non-existing basket fails', async () => {
    const res = await request(app).post('/rest/basket/42/checkout').set(authHeader)
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Basket with id=42 does not exist.'))
  })

  void it('POST placing an order for a basket with a negative total cost is possible', async () => {
    const itemRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 10, quantity: -100 })
    assert.equal(itemRes.status, 200)

    const res = await request(app).post('/rest/basket/3/checkout').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.orderConfirmation !== undefined)
  })

  void it('POST placing an order for a basket with 99% discount is possible', async () => {
    const couponRes = await request(app)
      .put('/rest/basket/2/coupon/' + encodeURIComponent(forgedCoupon))
      .set(authHeader)
    assert.equal(couponRes.status, 200)
    assert.ok(couponRes.headers['content-type']?.includes('application/json'))
    assert.equal(couponRes.body.discount, 99)

    const res = await request(app).post('/rest/basket/2/checkout').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.orderConfirmation !== undefined)
  })

  void describe('error cases', () => {
    void it('should return 500 if QuantityModel.findOne fails during checkout', async (t) => {
      const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
      const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
      await request(app).post('/api/BasketItems').set(authHeader).send({ BasketId: 4, ProductId: 1, quantity: 1 })

      t.mock.method(QuantityModel, 'findOne', () => { throw new Error('Quantity error') })
      const res = await request(app).post('/rest/basket/4/checkout').set(authHeader)
      assert.equal(res.status, 500)
      assert.match(res.text, /Quantity error/)
    })

    void it('should return 500 if WalletModel.findOne fails during checkout', async (t) => {
      const { token } = await login(app, { email: 'admin@' + config.get<string>('application.domain'), password: 'admin123' })
      const adminAuthHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
      await request(app).post('/api/BasketItems').set(adminAuthHeader).send({ BasketId: 1, ProductId: 1, quantity: 1 })
      t.mock.method(WalletModel, 'findOne', () => { throw new Error('Wallet error') })

      const res = await request(app).post('/rest/basket/1/checkout').set(adminAuthHeader).send({ orderDetails: { paymentId: 'wallet' }, UserId: 1 })
      assert.equal(res.status, 500)
      assert.match(res.text, /Wallet error/)
    })

    void it('should return 500 if ordersCollection.insert fails during checkout', async (t) => {
      const { token } = await login(app, { email: 'admin@' + config.get<string>('application.domain'), password: 'admin123' })
      const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
      await request(app).post('/api/BasketItems').set(authHeader).send({ BasketId: 1, ProductId: 1, quantity: 1 })

      t.mock.method(db.ordersCollection, 'insert', async () => { throw new Error('Insert error') })
      const res = await request(app).post('/rest/basket/1/checkout').set(authHeader)
      assert.equal(res.status, 500)
      assert.match(res.text, /Insert error/)
    })
  })
})

void describe('/rest/basket/:id/checkout order confirmation file', () => {
  void it('POST placing an order with non-string couponData is refused before an order file is opened', async (t) => {
    const orderFileStreams = spyOnOrderFileStreams(t)
    const statuses: number[] = []
    for (const couponData of [1, true, { code: 'WMNSDY2019' }]) {
      const res = await request(app).post('/rest/basket/1/checkout').set(authHeader).send({ couponData })
      statuses.push(res.status)
    }
    assert.deepEqual(statuses, [400, 400, 400])
    assert.deepEqual(orderFileStreams.map(({ file }) => file), [])
  })

  void it('POST placing an order with string couponData writes and closes a complete order confirmation PDF', async (t) => {
    const orderFileStreams = spyOnOrderFileStreams(t)
    const couponData = Buffer.from(`WMNSDY2019-${new Date('Mar 08, 2019 00:00:00 GMT+0100').getTime()}`).toString('base64')
    const res = await request(app).post('/rest/basket/1/checkout').set(authHeader).send({ couponData })
    assert.equal(res.status, 200)
    assert.ok(res.body.orderConfirmation !== undefined)
    assert.deepEqual(orderFileStreams.map(({ file }) => file), [path.join('ftp/', `order_${res.body.orderConfirmation}.pdf`)])

    const [{ stream, bytes }] = orderFileStreams
    if (!stream.closed) await once(stream, 'close')
    const pdf = Buffer.concat(bytes).toString('latin1')
    assert.ok(pdf.startsWith('%PDF-'))
    assert.ok(pdf.trimEnd().endsWith('%%EOF'))
  })

  void it('POST placing an order paid by wallet with insufficient balance fails without opening an order file', async (t) => {
    const { token } = await login(app, { email: 'admin@' + config.get<string>('application.domain'), password: 'admin123' })
    const adminAuthHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
    const orderFileStreams = spyOnOrderFileStreams(t)
    const res = await request(app)
      .post('/rest/basket/1/checkout')
      .set(adminAuthHeader)
      .send({ UserId: 1, orderDetails: { paymentId: 'wallet', deliveryMethodId: 1 } })
    assert.equal(res.status, 500)
    assert.match(res.text, /Insufficient wallet balance/)
    assert.deepEqual(orderFileStreams.map(({ file }) => file), [])
  })
})

void describe('/rest/basket/:id/coupon/:coupon', () => {
  void it('PUT apply valid coupon to existing basket', async () => {
    const res = await request(app)
      .put('/rest/basket/1/coupon/' + encodeURIComponent(validCoupon))
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.discount, 15)
  })

  void it('PUT apply invalid coupon is not accepted', async () => {
    const res = await request(app)
      .put('/rest/basket/1/coupon/xxxxxxxxxx')
      .set(authHeader)
    assert.equal(res.status, 404)
  })

  void it('PUT apply outdated coupon is not accepted', async () => {
    const res = await request(app)
      .put('/rest/basket/1/coupon/' + encodeURIComponent(outdatedCoupon))
      .set(authHeader)
    assert.equal(res.status, 404)
  })

  void it('PUT apply valid coupon to non-existing basket throws error', async () => {
    const res = await request(app)
      .put('/rest/basket/4711/coupon/' + encodeURIComponent(validCoupon))
      .set(authHeader)
    assert.equal(res.status, 500)
  })
})
