describe('challenge "Password Hash Leak"', () => {
  beforeEach(() => {
    cy.login({ email: 'admin@juice-sh.op', password: 'admin123' })
  })

  it('should not leak the password hash via the whoami fields parameter', () => {
    cy.request({
      method: 'GET',
      url: '/rest/user/whoami?fields=id,email,password',
      headers: {
        // Cypress automatically handles cookies after cy.login
      }
    }).then((res) => {
      // eslint-disable-next-line @typescript-eslint/no-unused-expressions
      expect(res.body.user.password).to.be.undefined
    })
  })
})
