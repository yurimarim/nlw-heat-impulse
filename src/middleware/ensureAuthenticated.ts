import { Request, Response, NextFunction } from "express"
import { verify } from "jsonwebtoken"

interface IPayLoad{
  sub: string
}


export function ensureAuthenticated(request: Request, response: Response, next: NextFunction) {
    const authToken = request.headers.authorization

    if(!authToken) {
      return response.status(401).json({
        errorCode: "token.invalid",
      })
    }

    //Bearer 89989843212654d8a6ahdfhafdh89f
    //[0] Bearer
    //[1] 89989843212654d8a6ahdfhafdh89f
    //Desestruturação
    // , -> primeira casa ignora, segunda casa guarda o dado na variável token.
    const [, token] = authToken.split(" ")

    try{ 
      const { sub } = verify(token, process.env.JWT_SECRET) as IPayLoad

      request.user_id = sub
      return next()
    }catch(err){
      return response.status(401).json({ errorCode: "token.expired" })
    }

}