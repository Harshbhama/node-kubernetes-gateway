import { Request, Response } from "express";
import { StatusCodes } from "http-status-codes";

export class Health {
  public health(_req: Request, res: Response): void {
    res.status(StatusCodes.OK).send('Api Gatwat service is healthy and ok');  
  }
}