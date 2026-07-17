describe('/#/basket', () => {
  describe('as admin', () => {
    beforeEach(() => {
      cy.login({ email: 'admin', password: 'admin123' })
    })

    describe('challenge "negativeOrder"', () => {
      // Security fix: quantityCheck (routes/basketItems.ts) now rejects any
      // non-positive quantity server-side, so a basket item can no longer be driven
      // negative via the Rest API - which also closes off placing an order with a
      // negative total (previously credited the wallet instead of charging it).
      it('should reject updating a basket item to a negative quantity via the Rest API', () => {
        cy.window().then(async () => {
          const response = await fetch(
            `${Cypress.config('baseUrl')}/api/BasketItems/1`,
            {
              method: 'PUT',
              cache: 'no-cache',
              headers: {
                'Content-type': 'application/json',
                Authorization: `Bearer ${localStorage.getItem('token')}`
              },
              body: JSON.stringify({ quantity: -100000 })
            }
          )
          expect(response.status).to.eq(400)
        })
        cy.visit('/#/order-summary')

        cy.get('mat-cell.mat-column-quantity > span')
          .first()
          .then(($ele) => {
            const quantity = $ele.text()
            expect(quantity).not.to.match(/-100000/)
          })
      })
    })

    describe('challenge "basketAccessChallenge"', () => {
      it('should access basket with id from session storage instead of the one associated to logged-in user', () => {
        cy.window().then(() => {
          window.sessionStorage.bid = 3
        })

        cy.visit('/#/basket')

        // TODO Verify functionally that it's not the basket of the admin
        cy.expectChallengeSolved({ challenge: 'View Basket' })
      })
    })

    describe('challenge "basketManipulateChallenge"', () => {
      it('should manipulate basket of other user instead of the one associated to logged-in user', () => {
        cy.window().then(async () => {
          await fetch(`${Cypress.config('baseUrl')}/api/BasketItems/`, {
            method: 'POST',
            cache: 'no-cache',
            headers: {
              'Content-type': 'application/json',
              Authorization: `Bearer ${localStorage.getItem('token')}`
            },
            body: '{ "ProductId": 14,"BasketId":"1","quantity":1,"BasketId":"2" }'
          })
        })
        cy.expectChallengeSolved({ challenge: 'Manipulate Basket' })
      })
    })
  })

  describe('as jim', () => {
    beforeEach(() => {
      cy.login({ email: 'jim', password: 'ncc-1701' })
    })
    describe('challenge "manipulateClock"', () => {
      // Security fix: calculateApplicableDiscount (routes/order.ts) now checks the
      // campaign redemption window against the server's own clock, not just a
      // client-supplied date. Manipulating the browser's local Date() can still make
      // the coupon look accepted client-side, but the server independently rejects a
      // years-old campaign code, so no discount should ever be applied at checkout.
      it('should not receive a discount for an expired campaign coupon even after manipulating the local clock to match it', () => {
        cy.window().then(() => {
          window.localStorage.couponPanelExpanded = false
        })
        cy.visit('/#/payment/shop')

        cy.window().then((win) => {
          cy.on('uncaught:exception', (_err, _runnable) => {
            // Introduced to disable the uncaught:exception we get after the eval under this as TypeError: Date.now is not a function
            return false
          })
          win.eval(
            'event = new Date("March 08, 2019 00:00:00"); Date = function(Date){return function() {date = event; return date; }}(Date);'
          )
        })
        cy.get('#collapseCouponElement').click()

        cy.get('#coupon').type('WMNSDY2019')
        cy.get('#applyCouponButton').click()
        cy.get('.mat-mdc-radio-button').first().click()
        cy.get('.nextButton').click()
        cy.get('#checkoutButton').click()

        cy.window().then((win) => {
          cy.request({
            url: '/rest/order-history',
            headers: { Authorization: `Bearer ${win.localStorage.getItem('token')}` }
          }).then((response) => {
            const orders = response.body.data
            const lastOrder = orders[orders.length - 1]
            expect(Number(lastOrder.promotionalAmount)).to.eq(0)
          })
        })
      })
    })

    describe('challenge "forgedCoupon"', () => {
      it('should be able to access file /ftp/coupons_2013.md.bak with poison null byte attack', () => {
        cy.request(`${Cypress.config('baseUrl')}/ftp/coupons_2013.md.bak%2500.md`)
      })

      it('should be possible to add a product in the basket', () => {
        cy.window().then(async () => {
          const response = await fetch(
            `${Cypress.config('baseUrl')}/api/BasketItems/`,
            {
              method: 'POST',
              cache: 'no-cache',
              headers: {
                'Content-type': 'application/json',
                Authorization: `Bearer ${localStorage.getItem('token')}`
              },
              body: JSON.stringify({
                BasketId: `${sessionStorage.getItem('bid')}`,
                ProductId: 1,
                quantity: 1
              })
            }
          )
          if (response.status === 201) {
            console.log('Success')
          }
        })
      })

      it('should be possible to enter a coupon that gives an 80% discount', () => {
        cy.window().then(() => {
          window.localStorage.couponPanelExpanded = false
        })

        cy.visit('/#/payment/shop')
        cy.get('#collapseCouponElement').click()
        cy.task<string>('GenerateCoupon', 90).then((coupon: string) => {
          cy.get('#coupon').type(coupon)
          cy.get('#applyCouponButton').click()
        })
      })

      it('should be possible to place an order with a forged coupon', () => {
        cy.visit('/#/order-summary')
        cy.get('#checkoutButton').click()
        cy.expectChallengeSolved({ challenge: 'Forged Coupon' })
      })
    })
  })
})
