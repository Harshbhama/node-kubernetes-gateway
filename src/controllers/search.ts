import { authService } from "@gateway/services/api/auth.service";
import { AxiosResponse } from "axios";
import { Request, Response } from "express";
import { StatusCodes } from "http-status-codes";

export class Search {
  public async gigById(req: Request, res: Response): Promise <void> {
    const response: AxiosResponse = await authService.getGig(req.params.gigId);
    res.status(StatusCodes.OK).json({ message: response.data.message, gig: response.data.gig});
  }
  public async gigs(req: Request, res: Response): Promise <void> {
    const { from, size, type } = req.params;
    console.log('Query Before',req.query);
    let query = '';
    const objList = Object.entries(req.query);
    const lastItemIndex = objList.length-1;
    objList.forEach(([key, value], index) => {
      query += `${key}=${value}${index !== lastItemIndex ? '&': ''}`;
    });
    console.log('Query After',query);
    const response: AxiosResponse = await authService.getGigs(`${query}`, from, size, type);
    res.status(StatusCodes.OK).json({ message: response.data.message, total: response.data.total ,gig: response.data.gigs});
  }
}