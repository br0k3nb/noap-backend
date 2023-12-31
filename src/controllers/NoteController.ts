import { Request, Response } from 'express';

import { Types } from 'mongoose';
import Note from '../models/Note';
import NoteState from '../models/NoteState';

export default {
    async view(req: Request, res: Response) {
        try {
            const { author, page } = req.params as any;
            if(!author || !page) return res.status(404).json({ message: "Access denied!" });

            const { search, limit, pinnedNotesPage } = req.query as any;

            const searchRegex = new RegExp(search as string, 'i');

            if(!(search as string).length) {
                const aggregate = Note.aggregate(
                    [
                        {
                            $match: {
                                author,
                                'settings.pinned': false,
                            }
                        },
                        {
                            $project: {
                                author:1, 
                                name: 1,
                                body: 1,
                                image: 1,
                                settings: 1,
                                labels: 1,
                                labelArraySize: { 
                                    $cond: {
                                        if: { $isArray: "$labels" },
                                        then: { $size: "$labels" },
                                        else: 0
                                    }
                                },
                                createdAt: 1,
                                updatedAt: 1,
                            }
                        },
                        {
                            $lookup: {
                                from: "labels",
                                localField: "labels",
                                foreignField: "_id",
                                as: "labels"
                            }
                        },
                        {   $unwind: {
                                path: '$labels',
                                preserveNullAndEmptyArrays: true
                            }
                        },
                        {
                            $group: {
                                _id: "$_id",
                                author: { $first: "$author" },
                                name: { $first: "$name"},
                                body: { $first: "$body"},
                                image: { $first: "$image" },
                                settings: { $first: "$settings" },
                                label: { $first: "$labels" },
                                labelArraySize: {$first: "$labelArraySize"},
                                createdAt: { $first: "$createdAt" },
                                updatedAt: { $first: "$updatedAt" }
                            }
                        },
                        {
                            $sort: { createdAt: 1 }
                        }
                    ]
                );

                const aggregatePinnedNotes = Note.aggregate(
                    [
                        {
                            $match: {
                                author,
                                'settings.pinned': true
                            }
                        },
                        {
                            $project: {
                                author:1, 
                                name: 1,
                                body: 1,
                                image: 1,
                                settings: 1,
                                labels: 1,
                                labelArraySize: { 
                                    $cond: { 
                                        if: { $isArray: "$labels" }, 
                                        then: { $size: "$labels" }, 
                                        else: 0
                                    } 
                                },
                                createdAt: 1,
                                updatedAt: 1,
                            }
                        },
                        {
                            $lookup: {
                                from: "labels",
                                localField: "labels",
                                foreignField: "_id",
                                as: "labels"
                            }
                        },
                        {   $unwind: {
                                path: '$labels',
                                preserveNullAndEmptyArrays: true
                            }
                        },
                        {
                            $group: {
                                _id: "$_id",
                                author: { $first: "$author" },
                                name: { $first: "$name"},
                                body: { $first: "$body"},
                                image: { $first: "$image" },
                                settings: { $first: "$settings" },
                                label: { $first: "$labels" },
                                labelArraySize: {$first: "$labelArraySize"},
                                createdAt: { $first: "$createdAt" },
                                updatedAt: { $first: "$updatedAt" }
                            }
                        },
                        {
                            $sort: { createdAt: 1 }
                        }
                    ]
                );    

                const notes = await Note.aggregatePaginate(aggregate, { page, limit });
                const pinnedNotes = await Note.aggregatePaginate(aggregatePinnedNotes, { 
                    page: pinnedNotesPage, 
                    limit: 10
                });

                return res.status(200).json({ notes, pinnedNotes });
            };

            if((search as string).length > 0) {
                const aggregate = Note.aggregate(
                    [
                        {
                            $match: { author }
                        }, 
                        {
                            $project: {
                                author:1, 
                                name: 1,
                                body: 1,
                                image: 1,
                                settings: 1,
                                labels: 1,
                                labelArraySize: { 
                                    $cond: { 
                                        if: { $isArray: "$labels" }, 
                                        then: { $size: "$labels" }, 
                                        else: 1
                                    } 
                                },
                                createdAt: 1,
                                updatedAt: 1,
                            }
                        },
                        {
                            $lookup: {
                                from: "labels",
                                localField: "labels",
                                foreignField: "_id",
                                as: "labels"
                            }
                        },
                        {   $unwind: {
                                path: '$labels',
                                preserveNullAndEmptyArrays: true
                            }
                        },
                        {
                            $match: {
                                $and: [
                                    { 
                                        $or: [
                                            { 'name': searchRegex },
                                            { 'body': searchRegex },
                                            { 'labels.name': searchRegex }
                                        ] 
                                    },
                                ]
                              }
                        }, 
                        {
                            $group: {
                                _id: "$_id",
                                author: { $first: "$author" },
                                name: { $first: "$name"},
                                body: { $first: "$body"},
                                image: { $first: "$image" },                                
                                settings: { $first: "$settings" },
                                label: { $first: "$labels" },
                                labelArraySize: { $first: "$labelArraySize" },
                                createdAt: { $first: "$createdAt" },
                                updatedAt: { $first: "$updatedAt" }
                            }
                        },
                        {
                            $sort: { createdAt: 1 }
                        }
                    ]
                    
                );

                const notes = await Note.aggregatePaginate(aggregate, { page, limit });
                return res.status(200).json({ notes, pinnedNotes: {} });
            }

        } catch (err) {
            res.status(400).json({ message: err });
            console.log(err);
        }
    },
    async getNote(req: Request, res: Response) {
        try {
            const { id } = req.params;
            const { author } = req.query;

            const aggregate = Note.aggregate(
                [
                    {
                        //@ts-ignore
                        $match: { _id: Types.ObjectId(id) }
                    }, 
                    {
                        $lookup: {
                          from: 'noteStates', 
                          localField: 'state', 
                          foreignField: '_id', 
                          as: 'state'
                        }
                    }, 
                    {
                        $unwind: {
                            path: '$state', 
                            preserveNullAndEmptyArrays: false
                        }
                    },
                    {
                        $lookup: {
                            from: "labels",
                            localField: "labels",
                            foreignField: "_id",
                            as: "labels"
                        }
                    },
                    {   $unwind: {
                            path: '$labels',
                            preserveNullAndEmptyArrays: true
                        }
                    },
                    {
                        $group: {
                            _id: "$_id",
                            author: { $first: "$author" },
                            name: { $first: "$name"},
                            body: { $first: "$body"},
                            image: { $first: "$image" },
                            state: { $first: "$state" },
                            settings: { $first: "$settings" },
                            labels: { $push: "$labels" },
                            createdAt: { $first: "$createdAt" },
                            updatedAt: { $first: "$updatedAt" }
                        }
                    }
                ]
            );

            const noteData = await Note.aggregatePaginate(aggregate);

            if(noteData.docs && noteData.docs[0].author !== author) {
                return res.status(401).json({ message: "You don't have permission to access this note!", code: 1 });
            }

            res.status(200).json({ note: noteData.docs[0] });
        } catch (err) {
            console.log(err);
            res.status(400).json({ message: "Error fetching note contents" });
        }
    },
    async add(req: Request , res: Response) {
        try {
            const { name, body, image, state, author, settings, pageLocation } = req.body;

            const { _id } = await NoteState.create({ state });
            const { _id: noteId } = await Note.create({
                name, 
                body,
                image,
                state: _id,
                author,
                settings,
                pageLocation
            });

            await NoteState.findOneAndUpdate({ _id }, { noteId });
            
            res.status(200).json({ noteId: noteId.toString(), pageLocation, message: 'Saved susccessfuly!' });
        } catch (err) {
            console.log(err);
            res.status(400).json({ message: 'Error creating a new note, please try again or later' });
        }
    },
    async addLabel(req: Request , res: Response) {
        try {
            const { labels, noteId } = req.body;

            await Note.findOneAndUpdate({ _id: noteId }, { labels: [ ...labels ] });

            res.status(200).json({ message: 'Label attached!' });
        } catch (err) {
            console.log(err);
            res.status(400).json({ message: 'Error, please try again later!' });
        }
    },
    async edit(req: Request , res: Response) {
        try {
            const { _id, title, body, image, state, stateId } = req.body;

            await Note.findOneAndUpdate({ _id }, { title, body, image });
            await NoteState.findByIdAndUpdate({ _id: stateId }, { state });
            
            res.status(200).json({ message: 'Note updated!' });
        } catch (err) {
            res.status(400).json({ message: 'Error, please try again later!' });
        }
    },
    async delete(req: Request , res: Response) {
        try {
            const { id } = req.params;
            const { state } = await Note.findById({ _id: id });

            await NoteState.findByIdAndDelete(state);
            await Note.findByIdAndDelete(id);
            
            res.status(200).json({ message: 'Note deleted!' });
        } catch (err) {
            res.status(400).json({ message: 'Error, please try again later!' });
        }
    },
    async deleteLabel(req: Request, res: Response) {
        try {
            const { id, noteId } = req.params;

            const { labels } = await Note.findById({ _id: noteId });

            if(!labels) res.status(400).json({ message: "Note wasn't found!"});

            const filtredLabels = labels.filter((_id: string) => _id.toString() !== id);
            
            await Note.findByIdAndUpdate({ _id: noteId }, { labels: filtredLabels });
            
            res.status(200).json({ message: 'Label detached!' });
        } catch (err) {
            console.log(err);
            res.status(400).json({ message: 'Error, please try again later!' });
        }
    },
    async deleteAllLabels(req: Request , res: Response) {
        try {
            const { noteId } = req.params;
            
            await Note.findByIdAndUpdate({ _id: noteId }, { labels: [] });  

            res.status(200).json({ message: 'Labels detached!' });
        } catch (err) {
            res.status(400).json({ message: 'Error, please try again later!' });
        }
    },
    async pinNote(req: Request , res: Response) {
        try {
            const { noteId } = req.params;
            const { condition } = req.body;
            
            await Note.findByIdAndUpdate({ _id: noteId }, { 
                settings: {
                    pinned: condition
                }
            });  

            res.status(200).json({ message: `${condition ? "Note pinned!" : "Note unpinned!"}` });
        } catch (err) {
            res.status(400).json({ message: 'Error, please try again later!' });
        }
    },
    async renameNote(req: Request , res: Response) {
        try {
            const { id } = req.params;
            const { name } = req.body;
            
            await Note.findByIdAndUpdate({ _id: id }, { name });  

            res.status(200).json({ message: "Updated!" });
        } catch (err) {
            res.status(400).json({ message: 'Error, please try again later!' });
        }
    },
    async changeNoteBackgroundColor(req: Request, res: Response) {
        try {
            const { noteId } = req.params;
            const { noteBackgroundColor } = req.body;

            const getNoteData = await Note.findById(noteId);

            await Note.findByIdAndUpdate({ _id: noteId }, {
                settings: {
                    ...getNoteData.settings,
                    noteBackgroundColor
                }
            });

            return res.status(200).json({ message: "Updated!" });
        } catch (err) {
            console.log(err);
            res.status(400).json({ message: err });
        }
    },
    async changeNoteImage(req: Request, res: Response) {
        try {
            const { noteId } = req.params;
            const { image } = req.body;

            await Note.findByIdAndUpdate({ _id: noteId }, { image });

            return res.status(200).json({ message: "Updated!" });
        } catch (err) {
            console.log(err);
            res.status(400).json({ message: err });
        }
    },
}