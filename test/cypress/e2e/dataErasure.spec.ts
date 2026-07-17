describe('/dataerasure', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })

  describe('layout parameter hardening', () => {
    it('should not be possible to perform a local file read attack via the `layout` body parameter', () => {
      cy.window().then(async () => {
        const params = 'layout=../package.json'

        const response = await fetch(`${Cypress.config('baseUrl')}/dataerasure`, {
          method: 'POST',
          cache: 'no-cache',
          headers: {
            'Content-type': 'application/x-www-form-urlencoded',
            Origin: `${Cypress.config('baseUrl')}/`,
            Cookie: `token=${localStorage.getItem('token')}`
          },
          body: params
        })
        const text = await response.text()
        expect(response.status).to.equal(200)
        expect(text).to.contain('Sorry to see you leave')
        expect(text).to.not.contain('"name": "juice-shop"')
      })
    })
  })
})
