describe('/#/deluxe-membership', () => {
  describe('challenge "svgInjection"', () => {
    it('should be possible to pass in a forgotten test parameter abusing the redirect-endpoint to load an external image', () => {
      cy.login({ email: 'jim', password: 'ncc-1701' })
      cy.location().then((loc) => {
        cy.visit(
          `/#/deluxe-membership?testDecal=${encodeURIComponent(
            `../../..${loc.pathname}/redirect?to=https://cataas.com/cat?x=https://github.com/juice-shop/juice-shop`
          )}`
        )
      })

      cy.expectChallengeSolved({ challenge: 'Cross-Site Imaging' })
    })
  })

  describe('challenge "freeDeluxe"', () => {
    // Security fix: /rest/deluxe-membership now rejects any paymentMode other than
    // 'wallet' or 'card' instead of silently granting deluxe for free, so this can no
    // longer be solved by omitting paymentMode.
    it('should reject a deluxe membership upgrade that omits paymentMode instead of granting it for free', () => {
      cy.login({
        email: 'jim',
        password: 'ncc-1701'
      })
      cy.visit('/#/')
      cy.getCookie('token').then((token) => {
        cy.request({
          url: '/rest/deluxe-membership',
          method: 'POST',
          headers: { Authorization: `Bearer ${token?.value}` },
          failOnStatusCode: false
        }).then((response) => {
          expect(response.status).to.eq(400)
          expect(response.body.status).contains('error')
        })
      })
    })
  })
})
