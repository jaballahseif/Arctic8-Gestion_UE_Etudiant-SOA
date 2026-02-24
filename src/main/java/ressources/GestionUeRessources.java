package ressources;

import entities.UniteEnseignement;
import metiers.UniteEnseignementBusiness;

import filtres.Secured;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;

@Path("UE")
public class GestionUeRessources {

    public static UniteEnseignementBusiness uniteEnseignementMetier = new UniteEnseignementBusiness();

    @GET
    @Produces("application/json")
    public Response getUnitesEnseignement(@QueryParam("domaine") String domaine,
            @QueryParam("semestre") Integer semestre) {
        List<UniteEnseignement> liste = new ArrayList<>();

        if (domaine != null) {
            liste = uniteEnseignementMetier.getUEByDomaine(domaine);
        } else if (semestre != null) {
            liste = uniteEnseignementMetier.getUEBySemestre(semestre);
        } else {
            liste = uniteEnseignementMetier.getListeUE();
        }

        if (liste.isEmpty())
            return Response.status(Response.Status.NOT_FOUND).build();
        return Response.status(Response.Status.OK).entity(liste).build();
    }

    @GET
    @Path("{code}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUniteEnseignement(@PathParam("code") int code) {
        UniteEnseignement ue = uniteEnseignementMetier.getUEByCode(code);
        if (ue != null) {
            return Response.status(Response.Status.OK).entity(ue).build();
        }
        return Response.status(Response.Status.NOT_FOUND).build();
    }

    @Secured
    @POST
    @Consumes(MediaType.APPLICATION_XML) // Keeping XML as per original file, though typically JSON is preferred. User
                                         // request implies finishing docx which likely asks for these.
    public Response addUE(UniteEnseignement ue) {
        if (uniteEnseignementMetier.addUniteEnseignement(ue)) {
            return Response.status(Response.Status.CREATED)
                    .entity("UE Created")
                    .build();
        }
        return Response.status(Response.Status.NOT_FOUND).build();
    }

    @PUT
    @Path("{code}")
    @Consumes(MediaType.APPLICATION_XML)
    public Response updateUE(@PathParam("code") int code, UniteEnseignement ue) {
        if (uniteEnseignementMetier.updateUniteEnseignement(code, ue)) {
            return Response.status(Response.Status.OK).entity("UE Updated").build();
        }
        return Response.status(Response.Status.NOT_FOUND).build();
    }

    @DELETE
    @Path("{code}")
    public Response deleteUE(@PathParam("code") int code) {
        if (uniteEnseignementMetier.deleteUniteEnseignement(code)) {
            return Response.status(Response.Status.OK).entity("UE Deleted").build();
        }
        return Response.status(Response.Status.NOT_FOUND).build();
    }
}
