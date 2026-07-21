export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (!user?.data?.email) {
      return res.sendStatus(401)
    }

    if (req.body.id['$ne'] !== undefined) {
      res.status(400).send()
      return
    }

    db.reviewsCollection.update(
      { _id: req.body.id, author: user.data.email },
      { $set: { message: req.body.message } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        if (result.modified === 0) {
          return res.sendStatus(404)
        }
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
